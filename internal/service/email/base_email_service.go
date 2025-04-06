package service

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"sync"
	"text/template"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	email "github.com/vigiloauth/vigilo/internal/domain/email"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ email.EmailService = (*BaseEmailService)(nil)
var logger = config.GetServerConfig().Logger()

const baseEmailService = "Base Email Service"

// BaseEmailService provides common email functionality.
type BaseEmailService struct {
	smtpConfig      *config.SMTPConfig
	template        *template.Template
	requests        []email.EmailRequest
	requestMutex    sync.Mutex
	getTemplateFunc func() string
	shouldRetryFunc func(time.Time, email.EmailRequest) bool
}

// Initialize sets up the base email service.
//
// Returns:
//
//	error: If an error occurs initializing the email service.
func (es *BaseEmailService) Initialize() error {
	smtpConfig := config.GetServerConfig().SMTPConfig()
	if smtpConfig == nil {
		logger.Warn(baseEmailService, "SMTP Configuration is not set, email functionality is disabled")
		return nil
	}

	if err := validateSMTPConfig(smtpConfig); err != nil {
		logger.Error(baseEmailService, "Initialize: Failed to validate SMTP credentials: %v", err)
		return errors.Wrap(err, errors.ErrCodeValidationError, "failed to validate SMTP Credentials")
	}

	if es.getTemplateFunc == nil {
		logger.Debug(baseEmailService, "Initialize: No email template function provided, defaulting to default template function")
		es.getTemplateFunc = es.getDefaultTemplate
	}

	if es.shouldRetryFunc == nil {
		logger.Debug(baseEmailService, "Initialize: No retry function provided, defaulting to default template function")
		es.shouldRetryFunc = es.shouldRetryEmail
	}

	es.smtpConfig = smtpConfig
	if err := es.loadEmailTemplate(); err != nil {
		logger.Error(baseEmailService, "Initialize: Failed to load email template: %v", err)
		return errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "failed to load email template")
	}

	return nil
}

// SendEmail sends an email based on the provided EmailRequest.
//
// Parameters:
//
//	request EmailRequest: The email request to send.
//
// Returns:
//
//	error: An error if sending the email fails.
func (es *BaseEmailService) SendEmail(request email.EmailRequest) error {
	if err := es.sendEmail(request); err != nil {
		es.requestMutex.Lock()
		defer es.requestMutex.Unlock()
		es.retryEmail(&request)
		logger.Error(baseEmailService, "SendEmail: Adding failed email delivery to retry queue: %v", err)
		return errors.Wrap(
			err, errors.ErrCodeEmailDeliveryFailed,
			"failed to deliver email, added to retry queue",
		)
	}

	return nil
}

// SetTemplate sets the email template to be used for sending emails.
//
// Parameters:
//
//	template string: The path to the email template.
//
// Returns:
//
//	error: An error if setting the template fails.
func (es *BaseEmailService) SetTemplate(tmplContent string) error {
	tmpl, err := template.New("email").Parse(tmplContent)
	if err != nil {
		logger.Error(baseEmailService, "SetTemplate: Failed to parse template content: %v", err)
		return errors.Wrap(
			err, errors.ErrCodeEmailTemplateParseFailed,
			"failed to parse email template",
		)
	}

	es.template = tmpl
	return nil
}

// TestConnection tests the connection to the SMTP server.
//
// Returns:
//
//	error: An error if the connection test fails.
func (es *BaseEmailService) TestConnection() error {
	client, err := es.createClient()
	if err != nil {
		logger.Error(baseEmailService, "TestConnection: Failed to create SMTP client: %v", err)
		return errors.Wrap(
			err, errors.ErrCodeSMTPServerConnectionFailed,
			"failed to create SMTP Client",
		)
	}
	defer client.Quit()

	logger.Info(baseEmailService, "TestConnection: Successfully connected to SMTP server")
	return nil
}

// ProcessQueue processes the email retry queue.
func (es *BaseEmailService) ProcessQueue() {
	logger.Info(baseEmailService, "ProcessQueue: Processing email queue")
	es.requestMutex.Lock()
	defer es.requestMutex.Unlock()

	var remainingRequests []email.EmailRequest
	now := time.Now()

	for _, request := range es.requests {
		if es.shouldRetryFunc(now, request) {
			if err := es.sendEmail(request); err != nil {
				es.retryEmail(&request)
				remainingRequests = append(remainingRequests, request)
			}
		} else {
			if request.RetryCount < es.smtpConfig.MaxRetries() {
				remainingRequests = append(remainingRequests, request)
			}
		}
	}

	logger.Info(baseEmailService, "ProcessQueue: Added %d requests to the queue", len(remainingRequests))
	es.requests = remainingRequests
}

// StartQueueProcessor starts a background process to periodically process the email queue.
//
// Parameters:
//
//	interval time.Duration: The interval between queue processing.
func (es *BaseEmailService) StartQueueProcessor(interval time.Duration) {
	logger.Info(baseEmailService, "StartQueueProcess: Starting queue processor with interval=[%s]", interval)
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			es.ProcessQueue()
		}
	}()
}

// GetQueueStatus returns the current status of the email queue, including queue length and retry counts.
//
// Returns:
//
//	int: The current length of the email queue.
//
//	map[string]int: A map of application IDs to retry counts.
func (es *BaseEmailService) GetQueueStatus() (int, map[string]int) {
	es.requestMutex.Lock()
	defer es.requestMutex.Unlock()

	recipients := make(map[string]int)
	for _, request := range es.requests {
		recipients[request.Recipient] = request.RetryCount
	}

	totalRequests := len(es.requests)
	logger.Info(baseEmailService, "GetQueueStatus: Total Requests in the queue=[%d]", totalRequests)
	return totalRequests, recipients
}

// ClearQueue clears the email queue.
func (es *BaseEmailService) ClearQueue() {
	es.requestMutex.Lock()
	defer es.requestMutex.Unlock()
	es.requests = []email.EmailRequest{}
	logger.Info(baseEmailService, "ClearQueue: Retry queue has been cleared")
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
func (es *BaseEmailService) sendEmail(request email.EmailRequest) error {
	if es.template == nil {
		logger.Error(baseEmailService, "Email template is empty")
		return errors.New(errors.ErrCodeEmptyInput, "'email template' cannot be empty")
	}

	var emailBody bytes.Buffer
	if err := es.template.Execute(&emailBody, request.TemplateData); err != nil {
		logger.Error(baseEmailService, "Failed to render email template: %v", err)
		return errors.Wrap(
			err, errors.ErrCodeTemplateRenderingFailed,
			"failed to render email template",
		)
	}

	message := es.buildMessage(request, emailBody)
	logger.Info(baseEmailService, "Attempting to send email with encryption to recipient=[%s]", common.TruncateSensitive(request.Recipient))
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
func (es *BaseEmailService) buildMessage(request email.EmailRequest, emailBody bytes.Buffer) string {
	// Create header
	from := es.smtpConfig.FromAddress()
	if es.smtpConfig.Credentials() != nil && es.smtpConfig.Credentials().Username() != "" {
		logger.Debug(baseEmailService, "Adding SMTP credentials to header, from=[%s], fromAddress=[%s]",
			common.TruncateSensitive(es.smtpConfig.FromName()),
			common.TruncateSensitive(es.smtpConfig.FromAddress()),
		)
		from = fmt.Sprintf("%s <%s>", es.smtpConfig.FromName(), es.smtpConfig.FromAddress())
	}

	message := fmt.Sprintf("From: %s\r\n", from)
	message += fmt.Sprintf("To: %s\r\n", request.Recipient)
	message += fmt.Sprintf("Subject: %s\r\n", request.Subject)
	message += "MIME-Version: 1.0\r\n"
	message += "Content-Type: text/html; charset=UTF-8\r\n"

	if es.smtpConfig.ReplyTo() != "" {
		logger.Debug(baseEmailService, "Adding reply-to=[%s] to email", common.TruncateSensitive(es.smtpConfig.ReplyTo()))
		message += fmt.Sprintf("Reply-To: %s\r\n", es.smtpConfig.ReplyTo())
	}

	message += "\r\n" + emailBody.String()
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
func (es *BaseEmailService) sendWithEncryption(recipient, message string) error {
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
			logger.Error(baseEmailService, "Failed to connect network address=[%s]: %v", common.SanitizeURL(serverAddress), err)
			return errors.Wrap(err, errors.ErrCodeTLSConnectionFailed, "failed to connect to given network address")
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, es.smtpConfig.Server())
		if err != nil {
			logger.Error(baseEmailService, "Failed to create a new SMTP client: %v", err)
			return errors.Wrap(err, errors.ErrCodeSMTPClientCreationFailed, "failed to create a new SMTP client")
		}
		defer client.Quit()

		if err := es.authenticateClient(client); err != nil {
			logger.Error(baseEmailService, "Failed to authenticate SMTP client: %v", err)
			return errors.Wrap(err, errors.ErrCodeSMTPAuthenticationFailed, "failed to authenticate client")
		}

		// Set sender and recipient
		if err = client.Mail(fromAddress); err != nil {
			logger.Error(baseEmailService, "Failed to initiate a mail transaction: %v", err)
			return errors.Wrap(err, errors.ErrCodeSMTPServerError, "failed to initiate a mail transaction")
		}

		if err = client.Rcpt(recipient); err != nil {
			logger.Error(baseEmailService, "Failed to initiate RCPT command to recipient=[%s]: %v", common.TruncateSensitive(recipient), err)
			return errors.Wrap(err, errors.ErrCodeSMTPServerError, "failed to initiate 'RCPT' command to the recipient")
		}

		// Send message
		w, err := client.Data()
		if err != nil {
			logger.Error(baseEmailService, "Failed to issue DATA command to the server=[%s]: %v", common.TruncateSensitive(serverAddress), err)
			return errors.Wrap(err, errors.ErrCodeSMTPServerError, "failed to issue 'DATA' command to the server")
		}

		_, err = w.Write(messageBytes)
		if err != nil {
			logger.Error(baseEmailService, "Failed to write message: %v", err)
			return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to write message")
		}

		err = w.Close()
		if err != nil {
			logger.Error(baseEmailService, "Failed to close io.WriterCloser: %v", err)
			return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to close 'io.WriterCloser'")
		}

		return nil

	default:
		logger.Error(baseEmailService, "Failed to send email with unsupported encryption=[%s]", es.smtpConfig.Encryption())
		return errors.New(
			errors.ErrCodeUnsupportedEncryptionType,
			fmt.Sprintf("'%s' is unsupported", string(es.smtpConfig.Encryption())))
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
func (es *BaseEmailService) authenticateClient(smtpClient *smtp.Client) error {
	if es.smtpConfig.Credentials() != nil &&
		es.smtpConfig.Credentials().Username() != "" {
		auth := smtp.PlainAuth("",
			es.smtpConfig.Credentials().Username(),
			es.smtpConfig.Credentials().Password(),
			es.smtpConfig.Server(),
		)
		if err := smtpClient.Auth(auth); err != nil {
			logger.Error(baseEmailService, "Failed to authenticate the SMTP client: %v", err)
			return errors.Wrap(
				err, errors.ErrCodeSMTPAuthenticationFailed,
				"failed to authenticate SMTP client",
			)
		}
	}

	return nil
}

func (es *BaseEmailService) loadEmailTemplate() error {
	var err error
	if es.smtpConfig.TemplatePath() != "" {
		es.template, err = template.ParseFiles(es.smtpConfig.TemplatePath())
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "failed to parse email template(s)")
		}
	} else {
		defaultTemplate := es.getTemplateFunc()
		if defaultTemplate == "" {
			return errors.New(errors.ErrCodeEmptyInput, "default template not provided")
		}

		es.template, err = template.New("default").Parse(defaultTemplate)
		if err != nil {
			return errors.Wrap(err, errors.ErrCodeEmailTemplateParseFailed, "failed to parse default template")
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
		return errors.New(errors.ErrCodeEmptyInput, "invalid or empty 'SMTP Server'")
	}

	if smtpConfig.Port() == 0 {
		smtpConfig.SetPort(config.DefaultSMTPPort)
	}

	if smtpConfig.Encryption() == "" {
		smtpConfig.SetEncryption(config.StartTLS)
	}

	if smtpConfig.FromAddress() == "" {
		return errors.New(errors.ErrCodeEmptyInput, "invalid or empty 'from_address'")
	}

	return nil
}

// retryEmail increments the retry count and adds the email request to the retry queue.
//
// Parameters:
//
//	request *EmailRequest: The email request to retry.
func (es *BaseEmailService) retryEmail(request *email.EmailRequest) {
	request.RetryCount++
	request.LastAttempt = time.Now()
	es.requests = append(es.requests, *request)
}

// createClient creates an SMTP client based on the configured encryption type.
//
// Returns:
//
//	*smtp.Client: The created SMTP client.
//	error: An error if client creation fails.
func (es *BaseEmailService) createClient() (*smtp.Client, error) {
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

// Template methods that should be overridden by concrete implementations

// GenerateEmailRequest generates an email request (to be implemented by subclasses).
func (es *BaseEmailService) GenerateEmailRequest(request email.EmailRequest) *email.EmailRequest {
	// This should be overridden by concrete implementations
	return nil
}

// getDefaultTemplate returns the default email template as a string.
//
// Returns:
//
//	string: The default email template.
func (es *BaseEmailService) getDefaultTemplate() string {
	return `<!DOCTYPE html>
<html>
<head>
    <title>Default Email Template</title>
</head>
<body>
    <h1>{{ .Title }}</h1>
    <p>{{ .Content }}</p>
</body>
</html>`
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
func (es *BaseEmailService) shouldRetryEmail(now time.Time, request email.EmailRequest) bool {
	if request.RetryCount >= es.smtpConfig.MaxRetries() {
		return false
	}

	if now.Sub(request.LastAttempt) < es.smtpConfig.RetryDelay() {
		return false
	}

	return true
}
