package email

import "time"

type EmailRequest struct {
	Recipient            string
	Subject              string
	TemplateData         map[string]any
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
