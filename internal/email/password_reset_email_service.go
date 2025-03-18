package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net/smtp"
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// Ensure PasswordResetEmailService implements the EmailService interface.
var _ EmailService = (*PasswordResetEmailService)(nil)

// PasswordResetEmailService handles email sending and queue processing.
type PasswordResetEmailService struct {
	smtpConfig    *config.SMTPConfig // SMTP server configuration.
	template      *template.Template // Email template.
	requests      []EmailRequest     // Queue of email requests.
	requestsMutex sync.Mutex         // Mutex for protecting the requests queue.
}

// NewPasswordResetEmailService creates a new PasswordResetEmailService instance.
//
// Returns:
//
//	*PasswordResetEmailService: A new PasswordResetEmailService instance.
//	error: An error if SMTP configuration is invalid or template loading fails.
func NewPasswordResetEmailService() (*PasswordResetEmailService, error) {
	smtpConfig := config.GetServerConfig().SMTPConfig()
	if smtpConfig == nil {
		return nil, errors.New(errors.ErrCodeEmptyInput, "SMTP Configuration is nil")
	}

	if err := validateSMTPConfig(smtpConfig); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeValidationError, "failed to validate SMTP Credentials")
	}

	ps := &PasswordResetEmailService{smtpConfig: smtpConfig}
	if err := ps.loadEmailTemplate(); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "Failed to load email template")
	}

	return ps, nil
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
func (ps *PasswordResetEmailService) SendEmail(request EmailRequest) error {
	err := ps.sendEmail(request)
	if err != nil {
		ps.requestsMutex.Lock()
		defer ps.requestsMutex.Unlock()
		ps.retryEmail(&request)
		return errors.Wrap(err, errors.ErrCodeEmailDeliveryFailed, err.Error())
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
func (ps *PasswordResetEmailService) GenerateEmail(request EmailRequest) *EmailRequest {
	if request.PasswordResetRequest.ExpiresIn == 0 {
		request.PasswordResetRequest.ExpiresIn = config.DefaultTTL
	}

	expiryTime := time.Now().Add(request.PasswordResetRequest.ExpiresIn)

	return &EmailRequest{
		Recipient: request.Recipient,
		Subject:   fmt.Sprintf("[%s] Password Reset Request", request.TemplateData.AppName),
		TemplateData: TemplateData{
			ResetURL:   request.PasswordResetRequest.ResetURL,
			Token:      request.PasswordResetRequest.ResetToken,
			ExpiryTime: expiryTime.Format(time.RFC1123),
			AppName:    request.ApplicationID,
			UserEmail:  request.Recipient,
		},
		PasswordResetRequest: &PasswordResetRequest{
			ResetToken:  request.PasswordResetRequest.ResetToken,
			TokenExpiry: expiryTime,
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
func (ps *PasswordResetEmailService) SetTemplate(tmplContent string) error {
	tmpl, err := template.New("email").Parse(tmplContent)
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "failed to parse email template")
	}

	ps.template = tmpl
	return nil
}

// TestConnection tests the connection to the SMTP server.
//
// Returns:
//
//	error: An error if the connection test fails.
func (ps *PasswordResetEmailService) TestConnection() error {
	client, err := ps.createClient()
	if err != nil {
		return errors.Wrap(err, errors.ErrCodeSMTPServerConnectionFailed, "failed to create SMTP Client")
	}
	defer client.Quit()
	return nil
}

// ProcessQueue processes the email retry queue.
func (ps *PasswordResetEmailService) ProcessQueue() {
	ps.requestsMutex.Lock()
	defer ps.requestsMutex.Unlock()

	var remainingRequests []EmailRequest
	now := time.Now()

	for _, request := range ps.requests {
		if ps.shouldRetryEmail(now, request) {
			remainingRequests = append(remainingRequests, request)
		}
	}

	ps.requests = remainingRequests
}

// StartQueueProcessor starts a background process to periodically process the email queue.
//
// Parameters:
//
//	interval time.Duration: The interval between queue processing.
func (ps *PasswordResetEmailService) StartQueueProcessor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			ps.ProcessQueue()
		}
	}()
}

// ClearQueue clears the email retry queue.
func (ps *PasswordResetEmailService) ClearQueue() {
	ps.requestsMutex.Lock()
	defer ps.requestsMutex.Unlock()
	ps.requests = []EmailRequest{}
}

// GetQueueStatus returns the current status of the email queue.
//
// Returns:
//
//	int: The number of emails in the queue.
//	map[string]int: A map of recipient email addresses to retry counts.
func (ps *PasswordResetEmailService) GetQueueStatus() (int, map[string]int) {
	ps.requestsMutex.Lock()
	defer ps.requestsMutex.Unlock()

	recipients := make(map[string]int)
	for _, request := range ps.requests {
		recipients[request.Recipient] = request.RetryCount
	}

	return len(ps.requests), recipients
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
func (ps *PasswordResetEmailService) sendEmail(request EmailRequest) error {
	if ps.template == nil {
		return errors.New(errors.ErrCodeEmptyInput, "`email template` cannot be nil")
	}

	var body bytes.Buffer
	if err := ps.template.Execute(&body, request.TemplateData); err != nil {
		return errors.Wrap(err, errors.ErrCodeTemplateRenderingFailed, "failed to render email template")
	}

	message := ps.buildMessage(request, body)
	return ps.sendWithEncryption(request.Recipient, message)
}

// loadEmailTemplate loads the email template from the configured path or uses the default template.
//
// Returns:
//
//	error: An error if loading the template fails.
func (ps *PasswordResetEmailService) loadEmailTemplate() error {
	var err error
	if ps.smtpConfig.TemplatePath() != "" {
		ps.template, err = template.ParseFiles(ps.smtpConfig.TemplatePath())
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "failed to parse email template(s)")
		}
	} else {
		// Use default template
		ps.template, err = template.New("default").Parse(ps.getDefaultTemplate())
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "failed to parse default template")
		}
	}
	return nil
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
func (ps *PasswordResetEmailService) buildMessage(request EmailRequest, body bytes.Buffer) string {
	// Create header
	from := ps.smtpConfig.FromAddress()
	if ps.smtpConfig.Credentials().Username() != "" {
		from = fmt.Sprintf("%s <%s>", ps.smtpConfig.FromName(), ps.smtpConfig.FromAddress())
	}

	message := fmt.Sprintf("From: %s\r\n", from)
	message += fmt.Sprintf("To: %s\r\n", request.Recipient)
	message += fmt.Sprintf("Subject: %s\r\n", request.Subject)
	message += "MIME-Version: 1.0\r\n"
	message += "Content-Type: text/html; charset=UTF-8\r\n"

	if ps.smtpConfig.ReplyTo() != "" {
		message += fmt.Sprintf("Reply-To: %s\r\n", ps.smtpConfig.ReplyTo())
	}

	message += "\r\n" + body.String()
	return message
}

// createClient creates an SMTP client based on the configured encryption type.
//
// Returns:
//
//	*smtp.Client: The created SMTP client.
//	error: An error if client creation fails.
func (ps *PasswordResetEmailService) createClient() (*smtp.Client, error) {
	serverAddress := fmt.Sprintf("%s:%d", ps.smtpConfig.Server(), ps.smtpConfig.Port())

	var client *smtp.Client
	var err error

	// Create client based on encryption type
	switch ps.smtpConfig.Encryption() {
	case config.TLS:
		// Connect with TLS
		tlsConfig := &tls.Config{ServerName: ps.smtpConfig.Server()}
		conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
		if err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeTLSConnectionFailed, "failed to connect to given network address")
		}

		client, err = smtp.NewClient(conn, ps.smtpConfig.Server())
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
		if ps.smtpConfig.Encryption() == config.StartTLS {
			tlsConfig := &tls.Config{ServerName: ps.smtpConfig.Server()}
			if err := client.StartTLS(tlsConfig); err != nil {
				return nil, errors.Wrap(err, errors.ErrCodeStartTLSFailed, "starttls failed")
			}
		}
	default:
		return nil, errors.New(
			errors.ErrCodeUnsupportedEncryptionType,
			fmt.Sprintf("`%s` is unsupported", string(ps.smtpConfig.Encryption())))
	}

	if err := ps.authenticateClient(client); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeSMTPAuthenticationFailed, "failed to authenticate SMTP client")
	}

	return client, nil
}

// shouldRetryEmail determines if an email should be retried based on retry
// count, delay, and if the reset token is still valid.
//
// Parameters:
//
//	now time.Time: The current time.
//	request EmailRequest: The email request to check.
//
// Returns:
//
//	bool: True if the email should be retried, false otherwise.
func (ps *PasswordResetEmailService) shouldRetryEmail(now time.Time, request EmailRequest) bool {
	maxRetries := ps.smtpConfig.MaxRetries()
	if request.RetryCount >= maxRetries {
		return false
	}

	if tokenIsExpired(request, now) {
		return false
	}

	if now.Sub(request.LastAttempt) < ps.smtpConfig.RetryDelay() {
		return true
	}

	if err := ps.sendEmail(request); err != nil {
		ps.retryEmail(&request)
		if request.RetryCount < ps.smtpConfig.MaxRetries() {
			return true
		}
	}

	return false
}

// retryEmail increments the retry count and adds the email request to the retry queue.
//
// Parameters:
//
//	request *EmailRequest: The email request to retry.
func (ps *PasswordResetEmailService) retryEmail(request *EmailRequest) {
	request.RetryCount++
	request.LastAttempt = time.Now()
	ps.requests = append(ps.requests, *request)
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
func (ps *PasswordResetEmailService) sendWithEncryption(recipient, message string) error {
	serverAddress := fmt.Sprintf("%s:%d", ps.smtpConfig.Server(), ps.smtpConfig.Port())
	fromAddress := ps.smtpConfig.FromAddress()
	recipients := []string{recipient}
	messageBytes := []byte(message)

	switch ps.smtpConfig.Encryption() {
	case config.None, config.StartTLS:
		auth := smtp.PlainAuth(
			"",
			ps.smtpConfig.Credentials().Username(),
			ps.smtpConfig.Credentials().Password(),
			ps.smtpConfig.Server(),
		)
		return smtp.SendMail(serverAddress, auth, fromAddress, recipients, messageBytes)

	case config.TLS:
		tlsConfig := &tls.Config{ServerName: ps.smtpConfig.Server()}
		conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeTLSConnectionFailed, "failed to connect to given network address")
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, ps.smtpConfig.Server())
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeSMTPClientCreationFailed, "failed to create a new SMTP client")
		}
		defer client.Quit()

		if err := ps.authenticateClient(client); err != nil {
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
			fmt.Sprintf("`%s` is unsupported", string(ps.smtpConfig.Encryption())))
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
func (ps *PasswordResetEmailService) authenticateClient(client *smtp.Client) error {
	if ps.smtpConfig.Credentials() != nil && ps.smtpConfig.Credentials().Username() != "" {
		auth := smtp.PlainAuth(
			"",
			ps.smtpConfig.Credentials().Username(),
			ps.smtpConfig.Credentials().Password(),
			ps.smtpConfig.Server(),
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

// validateSMTP config validates the servers SMTP configuration
//
// Parameters:
//
//	smtpConfig *config.SMTPConfig: The SMTP configuration.
//
// Returns:
//
//	error: If there is an error validating the configuration, otherwise nil.
func validateSMTPConfig(smtpConfig *config.SMTPConfig) error {
	if smtpConfig.Server() == "" {
		return errors.New(errors.ErrCodeEmptyInput, "invalid or empty `SMTP Server`")
	}

	if smtpConfig.Port() == 0 {
		smtpConfig.SetPort(config.DefaultSMTPPort)
	}

	if smtpConfig.Encryption() == "" {
		smtpConfig.SetEncryption(config.StartTLS)
	}

	if smtpConfig.FromAddress() == "" {
		return errors.New(errors.ErrCodeEmptyInput, "invalid or empty `from address`")
	}

	return nil
}

// getDefaultTemplate returns the default email template as a string.
//
// Returns:
//
//	string: The default email template.
func (ps *PasswordResetEmailService) getDefaultTemplate() string {
	return `
	<p>Hello,</p>
	<p>You have requested a password reset. Click the following link to reset your password:</p>
	<p><a href="{{.ResetURL}}">{{.ResetURL}}</a></p>
	<p>This link will expire in {{.ExpiryTime}} hours.</p>
	<p>If you did not request a password reset, please ignore this email.</p>
	<p>Sincerely,<br>{{.AppName}}</p>
	`
}

// tokenIsExpired checks to see if the password reset token is expired or not.
func tokenIsExpired(request EmailRequest, now time.Time) bool {
	return !request.PasswordResetRequest.TokenExpiry.IsZero() && now.After(request.PasswordResetRequest.TokenExpiry)
}
