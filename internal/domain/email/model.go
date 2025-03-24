package domain

import "time"

// EmailRequest represents a request to send an email.
type EmailRequest struct {
	Recipient            string                // Recipient's email address.
	Subject              string                // Email subject.
	TemplateData         TemplateData          // Data to be used in the email template.
	RetryCount           int                   // Number of times the email has been retried.
	LastAttempt          time.Time             // Timestamp of the last attempt to send the email.
	ApplicationID        string                // Identifier for the application sending the email.
	PasswordResetRequest *PasswordResetRequest // Password reset specific request data.
}

// PasswordResetRequest contains data specific to password reset emails.
type PasswordResetRequest struct {
	ResetToken  string        // Password reset token.
	ResetURL    string        // Password reset URL.
	TokenExpiry time.Time     // Expiry time of the reset token.
	ExpiresIn   time.Duration // Time duration until the token expires.
}

// TemplateData holds data to be used when rendering email templates.
type TemplateData struct {
	ResetURL   string // Password reset URL.
	Token      string // Password reset token.
	ExpiryTime string // Expiry time of the token (formatted as string).
	AppName    string // Name of the application.
	UserEmail  string // User's email address.
}

// Headers represents email headers.
type Headers struct {
	From        string // Sender's email address.
	To          string // Recipient's email address.
	Subject     string // Email subject.
	MimeVersion string // MIME version.
	ContentType string // Content type of the email.
	ReplyTo     string // Reply-to email address.
}

// NewPasswordResetRequest creates a new EmailRequest for password reset emails.
//
// Parameters:
//
//	userEmail string: Recipient's email address.
//	resetURL string: Password reset URL.
//	resetToken string: Password reset token.
//	tokenExpiry time.Time: Expiry time of the reset token.
//
// Returns:
//
//	EmailRequest: An EmailRequest instance configured for password reset.
func NewPasswordResetRequest(userEmail, resetURL, resetToken string, tokenExpiry time.Time) EmailRequest {
	return EmailRequest{
		Recipient: userEmail,
		PasswordResetRequest: &PasswordResetRequest{
			ResetURL:    resetURL,
			ResetToken:  resetToken,
			TokenExpiry: tokenExpiry,
		},
	}
}
