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

var _ EmailService = (*PasswordResetEmailService)(nil)

type PasswordResetEmailService struct {
	smtpConfig    *config.SMTPConfig
	template      *template.Template
	requests      []EmailRequest
	requestsMutex sync.Mutex
}

func NewPasswordResetEmailService() (*PasswordResetEmailService, error) {
	smtpConfig := config.GetServerConfig().SMTPConfig()
	if smtpConfig == nil {
		return nil, errors.NewEmptyInputError("SMTP Configuration")
	}

	if err := validateSMTPConfigFields(smtpConfig); err != nil {
		return nil, errors.Wrap(err, "Failed to validate SMTP Credentials")
	}

	ps := &PasswordResetEmailService{smtpConfig: smtpConfig}
	if err := ps.loadEmailTemplate(); err != nil {
		return nil, errors.Wrap(err, "Failed to load email template")
	}

	return ps, nil
}

func (ps *PasswordResetEmailService) GenerateEmail(request EmailRequest) *EmailRequest {
	expirationTime := request.PasswordResetRequest.ExpiresIn
	if expirationTime == 0 {
		request.PasswordResetRequest.ExpiresIn = config.DefaultTTL
	}

	expiryTime := time.Now().Add(expirationTime)
	templateData := generateTemplateData(request, expiryTime)

	return &EmailRequest{
		Recipient:    request.Recipient,
		Subject:      fmt.Sprintf("[%s] Password Reset Request", request.ApplicationID),
		TemplateData: templateData,
		PasswordResetRequest: &PasswordResetRequest{
			ResetToken:  request.PasswordResetRequest.ResetToken,
			TokenExpiry: expiryTime,
		},
	}
}

func (ps *PasswordResetEmailService) SendEmail(request EmailRequest) error {
	err := ps.sendEmail(request)
	if err != nil {
		ps.requestsMutex.Lock()
		defer ps.requestsMutex.Unlock()
		ps.retryEmail(request)
		return errors.NewEmailDeliveryError(err)
	}

	return nil
}

func (ps *PasswordResetEmailService) SetTemplate(tmplContent string) error {
	tmpl, err := template.New("email").Parse(tmplContent)
	if err != nil {
		return errors.NewEmailTemplateParseError(err)
	}

	ps.template = tmpl
	return nil
}

func (ps *PasswordResetEmailService) TestConnection() error {
	client, err := ps.createSMTPClient()
	if err != nil {
		return errors.Wrap(err, "Failed to create SMTP Client")
	}
	defer client.Quit()

	if err := ps.startTLS(client); err != nil {
		return errors.Wrap(err, "Failed to start TLS")
	}

	return ps.authenticateCredentials(client)
}

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

func (ps *PasswordResetEmailService) StartQueueProcessor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			ps.ProcessQueue()
		}
	}()
}

func (ps *PasswordResetEmailService) GetQueueStatus() (int, map[string]int) {
	ps.requestsMutex.Lock()
	defer ps.requestsMutex.Unlock()

	recipients := make(map[string]int)
	for _, request := range ps.requests {
		recipients[request.Recipient] = request.RetryCount
	}

	return len(ps.requests), recipients
}

func (ps *PasswordResetEmailService) sendEmail(request EmailRequest) error {
	if ps.template == nil {
		return errors.NewEmptyInputError("email template")
	}

	var body bytes.Buffer
	if err := ps.template.Execute(&body, request.TemplateData); err != nil {
		return errors.NewTemplateRenderingError(err)
	}

	headers := ps.generateHeaders(request)
	message := generateMessage(headers, body)

	auth := smtp.PlainAuth("", ps.smtpConfig.Credentials().Username(), ps.smtpConfig.Credentials().Password(), ps.smtpConfig.Server())
	serverAddress := fmt.Sprintf("%s:%d", ps.smtpConfig.Server(), ps.smtpConfig.Port())

	return ps.sendSMTPMail(serverAddress, ps.smtpConfig.FromAddress(), request.Recipient, message, auth)
}

func (ps *PasswordResetEmailService) sendMailTLS(recipients []string, message []byte) error {
	tlsConfig := &tls.Config{ServerName: ps.smtpConfig.Server()}
	serverAddress := fmt.Sprintf("%s:%d", ps.smtpConfig.Server(), ps.smtpConfig.Port())

	conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
	if err != nil {
		return errors.Wrap(err, "Failed to connect to given network address")
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, ps.smtpConfig.Server())
	if err != nil {
		return errors.Wrap(err, "Failed to create a new SMTP client")
	}
	defer client.Quit()

	if err := ps.authenticateCredentials(client); err != nil {
		return errors.Wrap(err, "Failed to authenticate SMTP credentials")
	}

	if err = client.Mail(ps.smtpConfig.FromAddress()); err != nil {
		return errors.Wrap(err, "Failed to initiate a mail transaction")
	}

	for _, recipient := range recipients {
		if err = client.Rcpt(recipient); err != nil {
			return errors.Wrap(err, "Failed to initiate RCPT command to the recipient")
		}
	}

	// send email body
	w, err := client.Data()
	if err != nil {
		return errors.Wrap(err, "Failed to issue DATA command to the server")
	}

	_, err = w.Write(message)
	if err != nil {
		return errors.Wrap(err, "Failed to write message")
	}

	err = w.Close()
	if err != nil {
		return errors.Wrap(err, "Failed to close `io.WriterCloser`")
	}

	return nil
}

func (ps *PasswordResetEmailService) loadEmailTemplate() error {
	if ps.smtpConfig.TemplatePath() != "" {
		template, err := template.ParseFiles(ps.smtpConfig.TemplatePath())
		if err != nil {
			message := fmt.Sprintf("failed to parse email template: %v", err.Error())
			return errors.NewInvalidFormatError("template", message)
		}
		ps.template = template
	} else {
		defaultTemplate := getDefaultTemplate()
		template, err := template.New("default").Parse(defaultTemplate)
		if err != nil {
			return errors.Wrap(err, "Failed to parse default template")
		}
		ps.template = template
	}
	return nil
}

func (ps *PasswordResetEmailService) createSMTPClient() (*smtp.Client, error) {
	serverAddress := fmt.Sprintf("%s:%d", ps.smtpConfig.Server(), ps.smtpConfig.Port())

	var client *smtp.Client
	var err error

	switch ps.smtpConfig.Encryption() {
	case config.TLS:
		client, err = ps.createTLSClient(serverAddress)
	case config.None, config.StartTLS:
		client, err = smtp.Dial(serverAddress)
	default:
		return nil, errors.NewUnsupportedEncryptionTypeError(string(ps.smtpConfig.Encryption()))
	}

	if err != nil {
		return nil, errors.NewSMTPServerConnectionError(err)
	}

	return client, nil
}

func (ps *PasswordResetEmailService) createTLSClient(serverAddress string) (*smtp.Client, error) {
	tlsConfig := &tls.Config{ServerName: serverAddress}
	conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
	if err != nil {
		return nil, errors.NewTLSConnectionError(err)
	}

	client, err := smtp.NewClient(conn, ps.smtpConfig.Server())
	if err != nil {
		return nil, errors.NewClientCreationError(err)
	}

	return client, nil
}

func (ps *PasswordResetEmailService) startTLS(client *smtp.Client) error {
	if ps.smtpConfig.Encryption() == config.StartTLS {
		tlsConfig := &tls.Config{ServerName: ps.smtpConfig.Server()}
		if err := client.StartTLS(tlsConfig); err != nil {
			return errors.NewStartTLSFailedError(err)
		}
	}

	return nil
}

func (ps *PasswordResetEmailService) authenticateCredentials(client *smtp.Client) error {
	if ps.smtpConfig.Credentials() != nil && ps.smtpConfig.Credentials().Username() != "" {
		auth := smtp.PlainAuth(
			"",
			ps.smtpConfig.Credentials().Username(),
			ps.smtpConfig.Credentials().Password(),
			ps.smtpConfig.Server(),
		)

		if err := client.Auth(auth); err != nil {
			return errors.NewSMTPAuthenticationError(err)
		}
	}

	return nil
}

func (ps *PasswordResetEmailService) generateHeaders(request EmailRequest) Headers {
	from := ps.smtpConfig.FromAddress()
	if ps.smtpConfig.Credentials().Username() != "" {
		from = fmt.Sprintf("%s <%s>", ps.smtpConfig.FromName(), ps.smtpConfig.FromAddress())
	}

	headers := Headers{
		From:        from,
		To:          request.Recipient,
		Subject:     request.Subject,
		MimeVersion: "1.0",
		ContentType: "text/html; charset=UTF-8",
	}

	if ps.smtpConfig.ReplyTo() != "" {
		headers.ReplyTo = ps.smtpConfig.ReplyTo()
	}

	return headers
}

func (ps *PasswordResetEmailService) retryEmail(request EmailRequest) {
	request.RetryCount++
	request.LastAttempt = time.Now()
	ps.requests = append(ps.requests, request)
}

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

	err := ps.sendEmail(request)
	if err != nil {
		ps.retryEmail(request)
		if request.RetryCount < ps.smtpConfig.MaxRetries() {
			return true
		}
	}

	return false
}

func (ps *PasswordResetEmailService) sendSMTPMail(serverAddress, fromAddress, recipient, message string, auth smtp.Auth) error {
	recipients := []string{recipient}
	messageBytes := []byte(message)

	switch ps.smtpConfig.Encryption() {
	case config.None, config.StartTLS:
		return smtp.SendMail(serverAddress, auth, fromAddress, recipients, messageBytes)
	case config.TLS:
		return ps.sendMailTLS(recipients, messageBytes)
	default:
		return errors.NewUnsupportedEncryptionTypeError(string(ps.smtpConfig.Encryption()))
	}
}

func generateMessage(headers Headers, body bytes.Buffer) string {
	message := ""
	message += fmt.Sprintf("From: %s\r\n", headers.From)
	message += fmt.Sprintf("To: %s\r\n", headers.To)
	message += fmt.Sprintf("Subject: %s\r\n", headers.Subject)
	message += fmt.Sprintf("MIME-Version: %s\r\n", headers.MimeVersion)
	message += fmt.Sprintf("Content-Type: %s\r\n", headers.ContentType)
	if headers.ReplyTo != "" {
		message += fmt.Sprintf("Reply-To: %s\r\n", headers.ReplyTo)
	}
	message += "\r\n" + body.String()

	return message
}
func generateTemplateData(request EmailRequest, expiryTime time.Time) TemplateData {
	return TemplateData{
		ResetURL:   request.PasswordResetRequest.ResetURL,
		Token:      request.PasswordResetRequest.ResetToken,
		ExpiryTime: expiryTime.Format(time.RFC1123),
		AppName:    request.ApplicationID,
		UserEmail:  request.Recipient,
	}
}

func validateSMTPConfigFields(smtpConfig *config.SMTPConfig) error {
	if smtpConfig.Server() == "" {
		return errors.NewEmptyInputError("SMTP server")
	}

	if smtpConfig.Port() == 0 {
		smtpConfig.SetPort(config.DefaultSMTPPort)
	}

	if smtpConfig.Encryption() == "" {
		smtpConfig.SetEncryption(config.StartTLS)
	}

	if smtpConfig.FromAddress() == "" {
		return errors.NewEmptyInputError("From Address")
	}

	return nil
}

func getDefaultTemplate() string {
	return `
	<p>Hello,</p>
	<p>You have requested a password reset. Click the following link to reset your password:</p>
	<p><a href="{{.ResetURL}}">{{.ResetURL}}</a></p>
	<p>This link will expire in {{.ExpireInHours}} hours ({{.ExpiryTime}}).</p>
	<p>If you did not request a password reset, please ignore this email.</p>
	<p>Sincerely,<br>{{.AppName}}</p>
	`
}

func tokenIsExpired(request EmailRequest, now time.Time) bool {
	return !request.PasswordResetRequest.TokenExpiry.IsZero() && now.After(request.PasswordResetRequest.TokenExpiry)
}
