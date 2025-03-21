package email

import (
	"fmt"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
)

// Ensure PasswordResetEmailService implements the EmailService interface.
var _ EmailService = (*PasswordResetEmailService)(nil)

// PasswordResetEmailService handles email sending and queue processing.
type PasswordResetEmailService struct {
	BaseEmailService
}

// NewPasswordResetEmailService creates a new PasswordResetEmailService instance.
//
// Returns:
//
//	*PasswordResetEmailService: A new PasswordResetEmailService instance.
//	error: An error if SMTP configuration is invalid or template loading fails.
func NewPasswordResetEmailService() (*PasswordResetEmailService, error) {
	service := &PasswordResetEmailService{}
	service.BaseEmailService.getTemplateFunc = service.getDefaultTemplate
	service.BaseEmailService.shouldRetryFunc = service.shouldRetryEmail

	if err := service.Initialize(); err != nil {
		return nil, err
	}

	return service, nil
}

// GenerateEmailRequest generates an EmailRequest for account locked notifications.
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

// shouldRetryEmail determines if an email should be retried based on
// retry count, delay, and if the reset token is expired.
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
	if request.RetryCount >= ps.smtpConfig.MaxRetries() {
		return false
	}

	if now.Sub(request.LastAttempt) < ps.smtpConfig.RetryDelay() {
		return false
	}

	return !resetTokenIsExpired(request, now)
}

// resetTokenIsExpired checks to see if the password reset token is expired or not.
func resetTokenIsExpired(request EmailRequest, now time.Time) bool {
	return !request.PasswordResetRequest.TokenExpiry.IsZero() &&
		now.After(request.PasswordResetRequest.TokenExpiry)
}
