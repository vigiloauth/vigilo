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

type PasswordResetService struct {
	smtpConfig    *config.SMTPConfig
	template      *template.Template
	requests      []EmailRequest
	requestsMutex sync.Mutex
}

func NewPasswordResetService(smtpConfig *config.SMTPConfig) (*PasswordResetService, error) {
	if err := validateSMTPConfigFields(smtpConfig); err != nil {
		return nil, err
	}

	ps := &PasswordResetService{smtpConfig: smtpConfig}
	if err := ps.loadEmailTemplate(); err != nil {
		return nil, err
	}

	return ps, nil
}

func (ps *PasswordResetService) GenerateEmail(request EmailRequest) *EmailRequest {
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

func (ps *PasswordResetService) SendEmail(request EmailRequest) error {
	err := ps.sendEmail(request)
	if err != nil {
		ps.requestsMutex.Lock()
		defer ps.requestsMutex.Unlock()
		ps.retryEmail(request)
		return errors.NewEmailDeliveryError(err)
	}

	return nil
}

func (ps *PasswordResetService) SetTemplate(tmplContent string) error {
	tmpl, err := template.New("email").Parse(tmplContent)
	if err != nil {
		return errors.NewEmailTemplateParseError(err)
	}

	ps.template = tmpl
	return nil
}

func (ps *PasswordResetService) TestConnection() error {
	client, err := ps.createSMTPClient()
	if err != nil {
		return err
	}
	defer client.Quit()

	if err := ps.startTLS(client); err != nil {
		return err
	}

	return ps.authenticateCredentials(client)
}

func (ps *PasswordResetService) ProcessQueue() {
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

func (ps *PasswordResetService) StartQueueProcessor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			ps.ProcessQueue()
		}
	}()
}

func (ps *PasswordResetService) GetQueueStatus() (int, map[string]int) {
	ps.requestsMutex.Lock()
	defer ps.requestsMutex.Unlock()

	recipients := make(map[string]int)
	for _, request := range ps.requests {
		recipients[request.Recipient] = request.RetryCount
	}

	return len(ps.requests), recipients
}

func (ps *PasswordResetService) sendEmail(request EmailRequest) error {
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

func (ps *PasswordResetService) sendMailTLS(recipients []string, message []byte) error {
	tlsConfig := &tls.Config{ServerName: ps.smtpConfig.Server()}
	serverAddress := fmt.Sprintf("%s:%d", ps.smtpConfig.Server(), ps.smtpConfig.Port())

	conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, ps.smtpConfig.Server())
	if err != nil {
		return err
	}
	defer client.Quit()

	if err := ps.authenticateCredentials(client); err != nil {
		return err
	}

	if err = client.Mail(ps.smtpConfig.FromAddress()); err != nil {
		return err
	}

	for _, recipient := range recipients {
		if err = client.Rcpt(recipient); err != nil {
			return err
		}
	}

	// send email body
	w, err := client.Data()
	if err != nil {
		return err
	}

	_, err = w.Write(message)
	if err != nil {
		return err
	}

	err = w.Close()
	if err != nil {
		return err
	}

	return nil
}

func (ps *PasswordResetService) loadEmailTemplate() error {
	if ps.smtpConfig.TemplatePath() != "" {
		template, err := template.ParseFiles(ps.smtpConfig.TemplatePath())
		if err != nil {
			message := fmt.Sprintf("failed to parse email template: %v", err.Error())
			return errors.NewInvalidFormatError("template", message)
		}

		ps.template = template
	}

	return nil
}

func (ps *PasswordResetService) createSMTPClient() (*smtp.Client, error) {
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

func (ps *PasswordResetService) createTLSClient(serverAddress string) (*smtp.Client, error) {
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

func (ps *PasswordResetService) startTLS(client *smtp.Client) error {
	if ps.smtpConfig.Encryption() == config.StartTLS {
		tlsConfig := &tls.Config{ServerName: ps.smtpConfig.Server()}
		if err := client.StartTLS(tlsConfig); err != nil {
			return errors.NewStartTLSFailedError(err)
		}
	}

	return nil
}

func (ps *PasswordResetService) authenticateCredentials(client *smtp.Client) error {
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

func (ps *PasswordResetService) generateHeaders(request EmailRequest) map[string]string {
	from := ps.smtpConfig.FromAddress()
	if ps.smtpConfig.Credentials().Username() != "" {
		from = fmt.Sprintf("%s <%s>", ps.smtpConfig.FromName(), ps.smtpConfig.FromAddress())
	}

	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = request.Recipient
	headers["Subject"] = request.Subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	if ps.smtpConfig.ReplyTo() != "" {
		headers["Reply-To"] = ps.smtpConfig.ReplyTo()
	}

	return headers
}

func (ps *PasswordResetService) retryEmail(request EmailRequest) {
	request.RetryCount++
	request.LastAttempt = time.Now()
	ps.requests = append(ps.requests, request)
}

func (ps *PasswordResetService) shouldRetryEmail(now time.Time, request EmailRequest) bool {
	if now.Sub(request.LastAttempt) < ps.smtpConfig.RetryDelay() {
		return true
	}

	if !request.PasswordResetRequest.TokenExpiry.IsZero() &&
		now.After(request.PasswordResetRequest.TokenExpiry) {
		return false
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

func (ps *PasswordResetService) sendSMTPMail(serverAddress, fromAddress, recipient, message string, auth smtp.Auth) error {
	switch ps.smtpConfig.Encryption() {
	case config.None, config.StartTLS:
		return smtp.SendMail(serverAddress, auth, fromAddress, []string{recipient}, []byte(message))
	case config.TLS:
		return ps.sendMailTLS([]string{recipient}, []byte(message))
	default:
		return errors.NewUnsupportedEncryptionTypeError(string(ps.smtpConfig.Encryption()))
	}
}

func generateMessage(headers map[string]string, body bytes.Buffer) string {
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body.String()

	return message
}

func generateTemplateData(request EmailRequest, expiryTime time.Time) map[string]any {
	return map[string]any{
		"ResetURL":      request.PasswordResetRequest.ResetURL,
		"Token":         request.PasswordResetRequest.ResetToken,
		"ExpiryTime":    expiryTime.Format(time.RFC1123),
		"ExpireInHours": request.PasswordResetRequest.ExpiresIn.Hours(),
		"AppName":       request.ApplicationID,
		"UserEmail":     request.Recipient,
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
