package email

import (
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

	if err := validateSMTPConfigFields(smtpConfig); err != nil {
		return nil, errors.Wrap(err, "Failed to validate SMTP Credentials")
	}

	return &EmailNotificationService{smtpConfig: smtpConfig}, nil
}

func (es *EmailNotificationService) SendEmail(request EmailRequest) error {
	return nil
}

func (es *EmailNotificationService) GenerateEmail(request EmailRequest) *EmailRequest {
	return nil
}

func (es *EmailNotificationService) SetTemplate(template string) error {
	return nil
}

func (es *EmailNotificationService) TestConnection() error {
	client, err := es.createSMTPClient()
	if err != nil {
		return errors.Wrap(err, "Failed to create SMTP Client")
	}
	defer client.Quit()

	if err := es.startTLS(client); err != nil {
		return errors.Wrap(err, "Failed to start TLS")
	}

	return es.authenticateCredentials(client)
}

func (es *EmailNotificationService) ProcessQueue() {
	es.requestMutex.Lock()
	defer es.requestMutex.Lock()

	var remainingRequests []EmailRequest
	now := time.Now()

	for _, request := range es.requests {
		if es.shouldRetryEmail(now, request) {
			remainingRequests = append(remainingRequests, request)
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

func (es *EmailNotificationService) GetQueueStatus() (int, map[string]int) {
	es.requestMutex.Lock()
	defer es.requestMutex.Lock()

	recipients := make(map[string]int)
	for _, request := range es.requests {
		recipients[request.Recipient] = request.RetryCount
	}

	return len(es.requests), recipients
}

func (es *EmailNotificationService) sendEmail(request EmailRequest) error {
	return nil
}

func (Es *EmailNotificationService) shouldRetryEmail(now time.Time, request EmailRequest) bool {
	return true
}

func (es *EmailNotificationService) retryEmail(request EmailRequest) {}

func (es *EmailNotificationService) authenticateCredentials(client *smtp.Client) error {
	return nil
}

func (es *EmailNotificationService) startTLS(client *smtp.Client) error {
	return nil
}

func (es *EmailNotificationService) createSMTPClient() (*smtp.Client, error) {
	return nil, nil
}
