package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"sync"
	"text/template"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// Ensure EmailNotificationService implements the EmailService interface.
var _ EmailService = (*EmailNotificationService)(nil)

// EmailNotificationService handles email sending and queue processing.
type EmailNotificationService struct {
	smtpConfig   *config.SMTPConfig // SMTP server configuration.
	template     *template.Template // Email template.
	requests     []EmailRequest     // Queue of email requests.
	requestMutex sync.Mutex         // Mutex for protecting the requests queue.
}

// NewEmailNotificationService creates a new EmailNotificationService instance.
//
// Returns:
//
//	*EmailNotificationService: A new EmailNotificationService instance.
//	error: An error if SMTP configuration is invalid or template loading fails.
func NewEmailNotificationService() (*EmailNotificationService, error) {
	smtpConfig := config.GetServerConfig().SMTPConfig()
	if smtpConfig == nil {
		return nil, errors.New(errors.ErrCodeEmptyInput, "SMTP Configuration is nil")
	}

	if err := validateSMTPConfig(smtpConfig); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeValidationError, "failed to validate SMTP Credentials")
	}

	es := &EmailNotificationService{smtpConfig: smtpConfig}
	if err := es.loadEmailTemplate(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "Failed to load email template")
	}

	return es, nil
}

// SendEmail sends an email or adds it to the retry queue if sending fails.
//
// Parameters:
//
//	request EmailRequest: The email request to send.
//
// Returns:
//
//	error: An error if sending the email fails.
func (es *EmailNotificationService) SendEmail(request EmailRequest) error {
	err := es.sendEmail(request)
	if err != nil {
		es.requestMutex.Lock()
		defer es.requestMutex.Unlock()
		es.retryEmail(&request)
		return errors.Wrap(err, errors.ErrCodeEmailDeliveryFailed, "email delivery failed, added to retry queue")
	}

	return nil
}

// GenerateEmail generates an EmailRequest for account locked notifications.
//
// Parameters:
//
//	request EmailRequest: The base email request.
//
// Returns:
//
//	*EmailRequest: The generated email request.
func (es *EmailNotificationService) GenerateEmail(request EmailRequest) *EmailRequest {
	return &EmailRequest{
		Recipient: request.Recipient,
		Subject:   fmt.Sprintf("[%s] Account Locked Notification", request.ApplicationID),
		TemplateData: TemplateData{
			AppName:   request.ApplicationID,
			UserEmail: request.Recipient,
		},
	}
}

// SetTemplate sets the email template from a string.
//
// Parameters:
//
//	tmplContent string: The template content.
//
// Returns:
//
//	error: An error if parsing the template fails.
func (es *EmailNotificationService) SetTemplate(tmplContent string) error {
	tmpl, err := template.New("email").Parse(tmplContent)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "failed to parse email template")
	}

	es.template = tmpl
	return nil
}

// TestConnection tests the connection to the SMTP server.
//
// Returns:
//
//	error: An error if the connection test fails.
func (es *EmailNotificationService) TestConnection() error {
	client, err := es.createClient()
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeSMTPServerConnectionFailed, "failed to create SMTP Client")
	}
	defer client.Quit()
	return nil
}

// ProcessQueue processes the email retry queue.
func (es *EmailNotificationService) ProcessQueue() {
	es.requestMutex.Lock()
	defer es.requestMutex.Unlock()

	var remainingRequests []EmailRequest
	now := time.Now()

	for _, request := range es.requests {
		if es.shouldRetryEmail(now, request) {
			if err := es.sendEmail(request); err != nil {
				request.RetryCount++
				request.LastAttempt = now
				remainingRequests = append(remainingRequests, request)
			}
		}
	}

	es.requests = remainingRequests
}

// StartQueueProcessor starts a background process to periodically process the email queue.
//
// Parameters:
//
//	interval time.Duration: The interval between queue processing.
func (es *EmailNotificationService) StartQueueProcessor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			es.ProcessQueue()
		}
	}()
}

// ClearQueue clears the email retry queue.
func (es *EmailNotificationService) ClearQueue() {
	es.requestMutex.Lock()
	defer es.requestMutex.Unlock()
	es.requests = []EmailRequest{}
}

// GetQueueStatus returns the current status of the email queue.
//
// Returns:
//
//	int: The number of emails in the queue.
//	map[string]int: A map of recipient email addresses to retry counts.
func (es *EmailNotificationService) GetQueueStatus() (int, map[string]int) {
	es.requestMutex.Lock()
	defer es.requestMutex.Unlock()

	recipients := make(map[string]int)
	for _, request := range es.requests {
		recipients[request.Recipient] = request.RetryCount
	}

	return len(es.requests), recipients
}

// sendEmail sends an email using the configured SMTP settings.
//
// Parameters:
//
//	request EmailRequest: The email request to send.
//
// Returns:
//
//	error: An error if sending the email fails.
func (es *EmailNotificationService) sendEmail(request EmailRequest) error {
	if es.template == nil {
		return errors.New(errors.ErrCodeEmptyInput, "`email template` cannot be nil")
	}

	var body bytes.Buffer
	if err := es.template.Execute(&body, request.TemplateData); err != nil {
		return errors.Wrap(err, errors.ErrCodeTemplateRenderingFailed, "failed to render email template")
	}

	message := es.buildMessage(request, body)
	return es.sendWithEncryption(request.Recipient, message)
}

// buildMessage constructs the email message from the request and body.
//
// Parameters:
//
//	request EmailRequest: The email request.
//	body bytes.Buffer: The email body.
//
// Returns:
//
//	string: The formatted email message.
func (es *EmailNotificationService) buildMessage(request EmailRequest, body bytes.Buffer) string {
	from := es.smtpConfig.FromAddress()
	if es.smtpConfig.Credentials() != nil && es.smtpConfig.Credentials().Username() != "" {
		from = fmt.Sprintf("%s <%s>", es.smtpConfig.FromName(), es.smtpConfig.FromAddress())
	}

	message := fmt.Sprintf("From: %s\r\n", from)
	message += fmt.Sprintf("To: %s\r\n", request.Recipient)
	message += fmt.Sprintf("Subject: %s\r\n", request.Subject)
	message += "MIME-Version: 1.0\r\n"
	message += "Content-Type: text/html; charset=UTF-8\r\n"

	if es.smtpConfig.ReplyTo() != "" {
		message += fmt.Sprintf("Reply-To: %s\r\n", es.smtpConfig.ReplyTo())
	}

	message += "\r\n" + body.String()
	return message
}

// sendWithEncryption sends an email with the configured encryption.
//
// Parameters:
//
//	recipient string: The recipient email address.
//	message string: The email message.
//
// Returns:
//
//	error: An error if sending the email fails.
func (es *EmailNotificationService) sendWithEncryption(recipient, message string) error {
	serverAddress := fmt.Sprintf("%s:%d", es.smtpConfig.Server(), es.smtpConfig.Port())
	fromAddress := es.smtpConfig.FromAddress()
	recipients := []string{recipient}
	messageBytes := []byte(message)

	switch es.smtpConfig.Encryption() {
	case config.None, config.StartTLS:
		auth := smtp.PlainAuth(
			"",
			es.smtpConfig.Credentials().Username(),
			es.smtpConfig.Credentials().Password(),
			es.smtpConfig.Server(),
		)
		return smtp.SendMail(serverAddress, auth, fromAddress, recipients, messageBytes)

	case config.TLS:
		tlsConfig := &tls.Config{ServerName: es.smtpConfig.Server()}
		conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeTLSConnectionFailed, "failed to connect to given network address")
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, es.smtpConfig.Server())
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeSMTPClientCreationFailed, "failed to create a new SMTP client")
		}
		defer client.Quit()

		if err := es.authenticateClient(client); err != nil {
			return errors.Wrap(err, errors.ErrCodeSMTPAuthenticationFailed, "failed to authenticate client")
		}

		// Set sender and recipient
		if err = client.Mail(fromAddress); err != nil {
			return errors.Wrap(err, errors.ErrCodeSMTPServerError, "failed to initiate a mail transaction")
		}

		if err = client.Rcpt(recipient); err != nil {
			return errors.Wrap(err, errors.ErrCodeSMTPServerError, "failed to initiate `RCPT` command to the recipient")
		}

		// Send message
		w, err := client.Data()
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeSMTPServerError, "failed to issue `DATA` command to the server")
		}

		_, err = w.Write(messageBytes)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to write message")
		}

		err = w.Close()
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to close `io.WriterCloser`")
		}

		return nil

	default:
		return errors.New(
			errors.ErrCodeUnsupportedEncryptionType,
			fmt.Sprintf("`%s` is unsupported", string(es.smtpConfig.Encryption())))
	}
}

// authenticateClient authenticates the SMTP client with the configured credentials.
//
// Parameters:
//
//	client *smtp.Client: The SMTP client to authenticate.
//
// Returns:
//
//	error: An error if authentication fails.
func (es *EmailNotificationService) authenticateClient(client *smtp.Client) error {
	if es.smtpConfig.Credentials() != nil && es.smtpConfig.Credentials().Username() != "" {
		auth := smtp.PlainAuth(
			"",
			es.smtpConfig.Credentials().Username(),
			es.smtpConfig.Credentials().Password(),
			es.smtpConfig.Server(),
		)

		if err := client.Auth(auth); err != nil {
			return errors.Wrap(
				err, errors.ErrCodeSMTPAuthenticationFailed,
				"failed to authenticate SMTP client",
			)
		}
	}

	return nil
}

// createClient creates an SMTP client based on the configured encryption type.
//
// Returns:
//
//	*smtp.Client: The created SMTP client.
//	error: An error if client creation fails.
func (es *EmailNotificationService) createClient() (*smtp.Client, error) {
	serverAddress := fmt.Sprintf("%s:%d", es.smtpConfig.Server(), es.smtpConfig.Port())

	var client *smtp.Client
	var err error

	// Create client based on encryption type
	switch es.smtpConfig.Encryption() {
	case config.TLS:
		// Connect with TLS
		tlsConfig := &tls.Config{ServerName: es.smtpConfig.Server()}
		conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeTLSConnectionFailed, "failed to connect to given network address")
		}

		client, err = smtp.NewClient(conn, es.smtpConfig.Server())
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeSMTPClientCreationFailed, "failed to create SMTP client")
		}
	case config.None, config.StartTLS:
		// Connect without encryption initially
		client, err = smtp.Dial(serverAddress)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeSMTPServerConnectionFailed, "failed to connect to SMTP server")
		}

		// Start TLS if needed
		if es.smtpConfig.Encryption() == config.StartTLS {
			tlsConfig := &tls.Config{ServerName: es.smtpConfig.Server()}
			if err := client.StartTLS(tlsConfig); err != nil {
				return nil, errors.Wrap(err, errors.ErrCodeStartTLSFailed, "starttls failed")
			}
		}
	default:
		return nil, errors.New(
			errors.ErrCodeUnsupportedEncryptionType,
			fmt.Sprintf("`%s` is unsupported", string(es.smtpConfig.Encryption())))
	}

	if err := es.authenticateClient(client); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeSMTPAuthenticationFailed, "failed to authenticate SMTP client")
	}

	return client, nil
}

// shouldRetryEmail determines if an email should be retried based on retry count and delay.
//
// Parameters:
//
//	now time.Time: The current time.
//	request EmailRequest: The email request to check.
//
// Returns:
//
//	bool: True if the email should be retried, false otherwise.
func (es *EmailNotificationService) shouldRetryEmail(now time.Time, request EmailRequest) bool {
	if request.RetryCount >= es.smtpConfig.MaxRetries() {
		return false
	}

	if now.Sub(request.LastAttempt) < es.smtpConfig.RetryDelay() {
		return false
	}

	return true
}

// loadEmailTemplate loads the email template from the configured path or uses the default template.
//
// Returns:
//
//	error: An error if loading the template fails.
func (es *EmailNotificationService) loadEmailTemplate() error {
	var err error
	if es.smtpConfig.TemplatePath() != "" {
		es.template, err = template.ParseFiles(es.smtpConfig.TemplatePath())
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "failed to parse email template(s)")
		}
	} else {
		es.template, err = template.New("default").Parse(es.getDefaultTemplate())
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "failed to parse default template")
		}
	}
	return nil
}

// retryEmail increments the retry count and adds the email request to the retry queue.
//
// Parameters:
//
//	request *EmailRequest: The email request to retry.
func (es *EmailNotificationService) retryEmail(request *EmailRequest) {
	request.RetryCount++
	request.LastAttempt = time.Now()
	es.requests = append(es.requests, *request)
}

// getDefaultTemplate returns the default email template as a string.
//
// Returns:
//
//	string: The default email template.
func (es *EmailNotificationService) getDefaultTemplate() string {
	return `
	<p>Hello,</p>
	<p>Your account has been locked due to too many failed login attempts. Please reset
	your password to unlock your account</p>
	<p>Sincerely,<br>{{.AppName}}</p>
	`
}
