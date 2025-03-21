package email

import "time"

// Ensure EmailNotificationService implements the EmailService interface.
var _ EmailService = (*EmailNotificationService)(nil)

// EmailNotificationService handles sending email notifications.
type EmailNotificationService struct {
	BaseEmailService
}

// NewEmailNotificationService creates a new EmailNotificationService instance.
//
// Returns:
//
//	*EmailNotificationService: A new EmailNotificationService instance.
//	error: An error if SMTP configuration is invalid or template loading fails.
func NewEmailNotificationService() (*EmailNotificationService, error) {
	service := &EmailNotificationService{}
	service.BaseEmailService.getTemplateFunc = service.getDefaultTemplate
	service.BaseEmailService.shouldRetryFunc = service.shouldRetryEmail

	if err := service.Initialize(); err != nil {
		return nil, err
	}

	return service, nil
}

// GenerateEmailRequest generates an EmailRequest for notifications.
//
// Parameters:
//
//	request EmailRequest: The base email request.
//
// Returns:
//
//	*EmailRequest: The generated email request.
func (es *EmailNotificationService) GenerateEmailRequest(request EmailRequest) *EmailRequest {
	return &EmailRequest{
		Recipient: request.Recipient,
		Subject:   request.Subject,
		TemplateData: TemplateData{
			AppName:   request.ApplicationID,
			UserEmail: request.Recipient,
		},
	}
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

func (es *EmailNotificationService) shouldRetryEmail(now time.Time, request EmailRequest) bool {
	return es.BaseEmailService.shouldRetryEmail(now, request)
}
