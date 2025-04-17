package service

import (
	"bytes"
	"text/template"
	"time"

	_ "embed"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	domain "github.com/vigiloauth/vigilo/internal/domain/email"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var (
	//go:embed templates/account_verification.html
	accountVerificationTemplate string

	//go:embed templates/account_deletion.html
	accountDeletionTemplate string

	_ domain.EmailService = (*emailService)(nil)
)

const (
	maxRetries int = 5
)

type emailService struct {
	smtpConfig  *config.SMTPConfig
	host        string
	port        int
	username    string
	password    string
	baseURL     string
	fromAddress string
	retryQueue  *domain.EmailRetryQueue
	mailer      domain.Mailer

	logger *config.Logger
	module string
}

func NewEmailService(mailer domain.Mailer) domain.EmailService {
	smtpConfig := config.GetServerConfig().SMTPConfig()
	service := &emailService{
		smtpConfig:  smtpConfig,
		host:        smtpConfig.Host(),
		port:        smtpConfig.Port(),
		username:    smtpConfig.Username(),
		password:    smtpConfig.Password(),
		baseURL:     config.GetServerConfig().BaseURL(),
		fromAddress: smtpConfig.FromAddress(),
		retryQueue:  &domain.EmailRetryQueue{},
		mailer:      mailer,

		logger: config.GetLogger(),
		module: "Email Service",
	}

	if err := service.TestConnection(); err != nil {
		service.logger.Warn(service.module, "SMTP Server is down. Requests will be added to the queue for future processing")
	}

	return service
}

func (s *emailService) SendEmail(request *domain.EmailRequest) error {
	if !s.smtpConfig.IsHealthy() {
		s.logger.Warn(s.module, "SMTP server is down. Adding the request to the retry queue for future processing.")
		s.retryQueue.Add(request)
		return nil
	}

	switch request.EmailType {
	case domain.AccountVerification:
		if err := s.sendEmail(request, common.VerifyEmailAddress); err != nil {
			return errors.Wrap(err, errors.ErrCodeEmailDeliveryFailed, "failed to send verification email")
		}
	case domain.AccountDeletion:
		if err := s.sendEmail(request, common.AccountDeletion); err != nil {
			return errors.Wrap(err, errors.ErrCodeEmailDeliveryFailed, "failed to send verification email")
		}
	}

	return nil
}

func (s *emailService) TestConnection() error {
	backoff := 5 * time.Second

	var lastError error
	for attempt := range maxRetries {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}

		err := s.connectToSMTPServer()
		if err == nil {
			if attempt > 0 {
				s.logger.Info(s.module, "SMTP connection restored after %d attempts", attempt)
			}
			s.updateSMTPServerStatus(true)
			return nil
		}

		lastError = err
		s.logger.Warn(s.module, "SMTP connection failed (attempt %d/%d): %v", attempt+1, maxRetries, err)
	}

	s.logger.Error(s.module, "SMTP connection check failed after %d attempts: %v", maxRetries, lastError)
	s.updateSMTPServerStatus(false)
	return lastError
}

func (s *emailService) GetEmailRetryQueue() *domain.EmailRetryQueue {
	return s.retryQueue
}

func (s *emailService) connectToSMTPServer() error {
	closer, err := s.mailer.Dial(s.host, s.port, s.username, s.password)
	if err != nil {
		s.logger.Error(s.module, "[TestConnection] Failed to connect to the SMTP server: %v", err)
		return errors.Wrap(err, errors.ErrCodeConnectionFailed, "failed to connect to the SMTP server")
	}

	closer.Close()
	return nil
}

func (s *emailService) sendEmail(request *domain.EmailRequest, subject string) error {
	body, err := s.generateEmailBody(request)
	if err != nil {
		return errors.Wrap(err, "", "failed to generate email template")
	}

	message := s.mailer.NewMessage(request, body, subject, s.fromAddress)
	if err := s.mailer.DialAndSend(s.host, s.port, s.username, s.password, message); err != nil {
		s.logger.Error(s.module, "Failed to send account verification email. Adding to retry queue: %v", err)
		return err
	}

	return nil
}

func (s *emailService) generateEmailBody(request *domain.EmailRequest) (string, error) {
	var body string
	var err error
	switch request.EmailType {
	case domain.AccountVerification:
		body, err = s.generateEmailTemplate(request, accountVerificationTemplate)
	case domain.AccountDeletion:
		body, err = s.generateEmailTemplate(request, accountDeletionTemplate)
	}

	if err != nil {
		return "", errors.Wrap(err, "", "failed to generate email template")
	}

	return body, nil
}

func (s *emailService) generateEmailTemplate(request *domain.EmailRequest, templateName string) (string, error) {
	tmpl, err := template.New("account_verification").Parse(templateName)
	if err != nil {
		s.logger.Error(s.module, "Failed to parse email template file: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to parse email template file")
	}

	request.BaseURL = s.baseURL
	var buf bytes.Buffer

	if err := tmpl.Execute(&buf, request); err != nil {
		s.logger.Error(s.module, "Failed to load email data into the template: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to execute template")
	}

	return buf.String(), nil
}

func (s *emailService) updateSMTPServerStatus(isHealthy bool) {
	s.smtpConfig.SetHealth(isHealthy)
}
