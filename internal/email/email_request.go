package email

import "time"

type EmailRequest struct {
	Recipient            string
	Subject              string
	TemplateData         TemplateData
	RetryCount           int
	LastAttempt          time.Time
	ApplicationID        string
	PasswordResetRequest *PasswordResetRequest
}

type PasswordResetRequest struct {
	ResetToken  string
	ResetURL    string
	TokenExpiry time.Time
	ExpiresIn   time.Duration
}

type TemplateData struct {
	ResetURL   string
	Token      string
	ExpiryTime string
	AppName    string
	UserEmail  string
}

type Headers struct {
	From        string
	To          string
	Subject     string
	MimeVersion string
	ContentType string
	ReplyTo     string
}

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
