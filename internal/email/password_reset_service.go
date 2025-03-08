package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"net/smtp"
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// TODO
// - Create new errors.
// - Refactor
// - Test

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
	if request.ExpiresIn == 0 {
		request.ExpiresIn = config.DefaultTTL
	}

	expiryTime := time.Now().Add(request.ExpiresIn)

	templateData := map[string]any{
		"ResetURL":      request.ResetURL,
		"Token":         request.ResetToken,
		"ExpiryTime":    expiryTime.Format(time.RFC1123),
		"ExpireInHours": request.ExpiresIn.Hours(),
		"AppName":       request.ApplicationID,
		"UserEmail":     request.Recipient,
	}

	return &EmailRequest{
		Recipient:    request.Recipient,
		Subject:      fmt.Sprintf("[%s] Password Reset Request", request.ApplicationID),
		TemplateData: templateData,
		ResetToken:   request.ResetToken,
		TokenExpiry:  expiryTime,
	}
}

func (ps *PasswordResetService) SendEmail(request EmailRequest) error {
	err := ps.sendEmail(request)
	if err != nil {
		ps.requestsMutex.Lock()
		request.RetryCount++
		request.LastAttempt = time.Now()
		ps.requests = append(ps.requests, request)
		ps.requestsMutex.Unlock()
		return fmt.Errorf("email delivery failed, added to retry queue: %w", err)
	}
	return nil
}

func (ps *PasswordResetService) SetTemplate(tmplContent string) error {
	tmpl, err := template.New("email").Parse(tmplContent)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	ps.template = tmpl
	return nil
}

func (ps *PasswordResetService) TestConnection() error {
	var client *smtp.Client
	var err error

	serverAddress := fmt.Sprintf("%s:%d", ps.smtpConfig.Server(), ps.smtpConfig.Port())

	switch ps.smtpConfig.Encryption() {
	case config.TLS:
		tlsConfig := &tls.Config{ServerName: ps.smtpConfig.Server()}
		conn, err := tls.Dial("tcp", serverAddress, tlsConfig)
		if err != nil {
			return fmt.Errorf("TLS connection failed: %w", err)
		}
		client, err = smtp.NewClient(conn, ps.smtpConfig.Server())
		if err != nil {
			return fmt.Errorf("error creating new client: %w", err)
		}
	case config.None, config.StartTLS:
		client, err = smtp.Dial(serverAddress)
	default:
		return fmt.Errorf("unsupported encryption type: %s", ps.smtpConfig.Encryption())
	}

	if err != nil {
		return fmt.Errorf("SMTP server connection failed: %w", err)
	}

	defer client.Quit()

	if ps.smtpConfig.Encryption() == config.StartTLS {
		if err = client.StartTLS(&tls.Config{ServerName: ps.smtpConfig.Server()}); err != nil {
			return fmt.Errorf("StartTLS failed: %w", err)
		}
	}

	if ps.smtpConfig.Credentials() != nil && ps.smtpConfig.Credentials().Username() != "" {
		auth := smtp.PlainAuth("", ps.smtpConfig.Credentials().Username(), ps.smtpConfig.Credentials().Password(), ps.smtpConfig.Server())
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	return nil
}

func (ps *PasswordResetService) ProcessQueue() {
	ps.requestsMutex.Lock()
	defer ps.requestsMutex.Unlock()

	var remainingRequests []EmailRequest
	now := time.Now()

	for _, request := range ps.requests {
		if now.Sub(request.LastAttempt) < ps.smtpConfig.RetryDelay() {
			remainingRequests = append(remainingRequests, request)
			continue
		}

		if !request.TokenExpiry.IsZero() && now.After(request.TokenExpiry) {
			log.Printf("Skipping expired password reset token for %s", request.Recipient)
			continue
		}

		// Attempt to send
		err := ps.sendEmail(request)
		if err != nil {
			request.RetryCount++
			request.LastAttempt = now

			if request.RetryCount < ps.smtpConfig.MaxRetries() {
				remainingRequests = append(remainingRequests, request)
			} else {
				log.Printf("Maximum retry attempts reaached for email to %s: %v", request.Recipient, err)
			}
		} else {
			log.Printf("Successfully sent queued email to %s", request.Recipient)
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
		return fmt.Errorf("template rendering failed: %w", err)
	}

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

	// construct message
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body.String()

	// prepare auth
	auth := smtp.PlainAuth("", ps.smtpConfig.Credentials().Username(), ps.smtpConfig.Credentials().Password(), ps.smtpConfig.Server())
	serverAddress := fmt.Sprintf("%s:%d", ps.smtpConfig.Server(), ps.smtpConfig.Port())

	// send email based on encryption type
	switch ps.smtpConfig.Encryption() {
	case config.None, config.StartTLS:
		return smtp.SendMail(serverAddress, auth, ps.smtpConfig.FromAddress(), []string{request.Recipient}, []byte(message))
	case config.TLS:
		return ps.sendMailTLS(auth, []string{request.Recipient}, []byte(message))
	default:
		return fmt.Errorf("unsupported encryption type: %s", ps.smtpConfig.Encryption())
	}
}

func (ps *PasswordResetService) sendMailTLS(auth smtp.Auth, recipients []string, message []byte) error {
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

	// authenticate
	if auth != nil {
		if err = client.Auth(auth); err != nil {
			return err
		}
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
