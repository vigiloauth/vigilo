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

var _ EmailService = (*EmailNotificationService)(nil)

type EmailNotificationService struct {
	smtpConfig   *config.SMTPConfig
	template     *template.Template
	requests     []EmailRequest
	requestMutex sync.Mutex
}

func NewEmailNotificationService() (*EmailNotificationService, error) {
	smtpConfig := config.GetServerConfig().SMTPConfig()
	if smtpConfig == nil {
		return nil, errors.NewEmptyInputError("SMTP Configuration")
	}

	if err := validateSMTPConfig(smtpConfig); err != nil {
		return nil, errors.Wrap(err, "Failed to validate SMTP Credentials")
	}

	es := &EmailNotificationService{smtpConfig: smtpConfig}
	if err := es.loadEmailTemplate(); err != nil {
		return nil, errors.Wrap(err, "Failed to load email template")
	}

	return es, nil
}

func (es *EmailNotificationService) SendEmail(request EmailRequest) error {
	err := es.sendEmail(request)
	if err != nil {
		es.requestMutex.Lock()
		defer es.requestMutex.Unlock()
		es.retryEmail(&request)
		return errors.NewEmailDeliveryError(err)
	}

	return nil
}

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

func (es *EmailNotificationService) SetTemplate(tmplContent string) error {
	tmpl, err := template.New("email").Parse(tmplContent)
	if err != nil {
		return errors.NewEmailTemplateParseError(err)
	}

	es.template = tmpl
	return nil
}

func (es *EmailNotificationService) TestConnection() error {
	client, err := es.createClient()
	if err != nil {
		return errors.Wrap(err, "Failed to create SMTP Client")
	}
	defer client.Quit()
	return nil
}

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

func (es *EmailNotificationService) StartQueueProcessor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			es.ProcessQueue()
		}
	}()
}

func (es *EmailNotificationService) ClearQueue() {
	es.requestMutex.Lock()
	defer es.requestMutex.Unlock()
	es.requests = []EmailRequest{}
}

func (es *EmailNotificationService) GetQueueStatus() (int, map[string]int) {
	es.requestMutex.Lock()
	defer es.requestMutex.Unlock()

	recipients := make(map[string]int)
	for _, request := range es.requests {
		recipients[request.Recipient] = request.RetryCount
	}

	return len(es.requests), recipients
}

func (es *EmailNotificationService) sendEmail(request EmailRequest) error {
	if es.template == nil {
		return errors.NewEmptyInputError("email template")
	}

	var body bytes.Buffer
	if err := es.template.Execute(&body, request.TemplateData); err != nil {
		return errors.NewTemplateRenderingError(err)
	}

	message := es.buildMessage(request, body)
	return es.sendWithEncryption(request.Recipient, message)
}

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
			return errors.Wrap(err, "Failed to connect to given network address")
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, es.smtpConfig.Server())
		if err != nil {
			return errors.Wrap(err, "Failed to create a new SMTP client")
		}
		defer client.Quit()

		if err := es.authenticateClient(client); err != nil {
			return errors.Wrap(err, "Failed to authenticate client")
		}

		// Set sender and recipient
		if err = client.Mail(fromAddress); err != nil {
			return errors.Wrap(err, "Failed to initiate a mail transaction")
		}

		if err = client.Rcpt(recipient); err != nil {
			return errors.Wrap(err, "Failed to initiate RCPT command to the recipient")
		}

		// Send message
		w, err := client.Data()
		if err != nil {
			return errors.Wrap(err, "Failed to issue DATA command to the server")
		}

		_, err = w.Write(messageBytes)
		if err != nil {
			return errors.Wrap(err, "Failed to write message")
		}

		err = w.Close()
		if err != nil {
			return errors.Wrap(err, "Failed to close `io.WriterCloser`")
		}

		return nil

	default:
		return errors.NewUnsupportedEncryptionTypeError(string(es.smtpConfig.Encryption()))
	}
}

func (es *EmailNotificationService) authenticateClient(client *smtp.Client) error {
	if es.smtpConfig.Credentials() != nil && es.smtpConfig.Credentials().Username() != "" {
		auth := smtp.PlainAuth(
			"",
			es.smtpConfig.Credentials().Username(),
			es.smtpConfig.Credentials().Password(),
			es.smtpConfig.Server(),
		)

		if err := client.Auth(auth); err != nil {
			return errors.NewSMTPAuthenticationError(err)
		}
	}

	return nil
}

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
			return nil, errors.NewTLSConnectionError(err)
		}

		client, err = smtp.NewClient(conn, es.smtpConfig.Server())
		if err != nil {
			return nil, errors.NewClientCreationError(err)
		}
	case config.None, config.StartTLS:
		// Connect without encryption initially
		client, err = smtp.Dial(serverAddress)
		if err != nil {
			return nil, errors.NewSMTPServerConnectionError(err)
		}

		// Start TLS if needed
		if es.smtpConfig.Encryption() == config.StartTLS {
			tlsConfig := &tls.Config{ServerName: es.smtpConfig.Server()}
			if err := client.StartTLS(tlsConfig); err != nil {
				return nil, errors.NewStartTLSFailedError(err)
			}
		}
	default:
		return nil, errors.NewUnsupportedEncryptionTypeError(string(es.smtpConfig.Encryption()))
	}

	if err := es.authenticateClient(client); err != nil {
		return nil, errors.Wrap(err, "Failed to authenticate client")
	}

	return client, nil
}

func (es *EmailNotificationService) shouldRetryEmail(now time.Time, request EmailRequest) bool {
	if request.RetryCount >= es.smtpConfig.MaxRetries() {
		return false
	}

	if now.Sub(request.LastAttempt) < es.smtpConfig.RetryDelay() {
		return false
	}

	return true
}

func (es *EmailNotificationService) loadEmailTemplate() error {
	var err error
	if es.smtpConfig.TemplatePath() != "" {
		es.template, err = template.ParseFiles(es.smtpConfig.TemplatePath())
		if err != nil {
			return errors.NewInvalidFormatError("template",
				fmt.Sprintf("failed to parse email template: %v", err.Error()))
		}
	} else {
		es.template, err = template.New("default").Parse(es.getDefaultTemplate())
		if err != nil {
			return errors.Wrap(err, "Failed to parse default template")
		}
	}
	return nil
}

func (es *EmailNotificationService) retryEmail(request *EmailRequest) {
	request.RetryCount++
	request.LastAttempt = time.Now()
	es.requests = append(es.requests, *request)
}

func (es *EmailNotificationService) getDefaultTemplate() string {
	return `
	<p>Hello,</p>
	<p>Your account has been locked due to too many failed login attempts. Please reset
	your password to unlock your account</p>
	<p>Sincerely,<br>{{.AppName}}</p>
	`
}
