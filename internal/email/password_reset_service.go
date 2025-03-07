package email

import (
	"fmt"
	"html/template"
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
)

type PasswordResetService struct {
	smtpConfig     config.SMTPConfig
	template       *template.Template
	queue          []EmailRequest
	queueMutex     sync.Mutex
	tokenValidator func(string) bool
}

func NewPasswordResetService(smtpConfig config.SMTPConfig) (*PasswordResetService, error) {
	if smtpConfig.Server() == "" {
		return nil, errors.NewEmptyInputError("SMTP server")
	}

	if smtpConfig.Port() == 0 {
		smtpConfig.SetPort(config.DefaultSMTPPort)
	}
	if smtpConfig.Encryption() == "" {
		smtpConfig.SetEncryption(config.StartTLS)
	}
	if smtpConfig.FromAddress() == "" {
		return nil, errors.NewEmptyInputError("From Address")
	}

	passwordResetService := &PasswordResetService{smtpConfig: smtpConfig}

	// Load template if a path was provided
	if smtpConfig.TemplatePath() != "" {
		template, err := template.ParseFiles(smtpConfig.TemplatePath())
		if err != nil {
			message := fmt.Sprintf("failed to parse email template: %w", err)
			return nil, errors.NewInvalidFormatError("template", message)
		}

		passwordResetService.template = template
	}

	return passwordResetService, nil
}

func (ps *PasswordResetService) SendMail(request EmailRequest) error {
	return nil
}

func (ps *PasswordResetService) SetTemplate(template string) error {
	return nil
}

func (ps *PasswordResetService) TestConnection() error {
	return nil
}

func (ps *PasswordResetService) ProcessQueue() {

}

func (ps *PasswordResetService) StartQueueProcessor(interval time.Duration) {

}

func (ps *PasswordResetService) GetQueueStatus() (int, map[string]int) {
	return 0, nil
}

func (ps *PasswordResetService) loadTemplate(smtpConfig config.SMTPConfig) error {
	return nil
}
