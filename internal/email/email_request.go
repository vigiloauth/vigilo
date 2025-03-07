package email

import "time"

type EmailRequest struct {
	Recipient    string
	Subject      string
	TemplateData map[string]any
	RetryCount   int
	LastAttempt  time.Time
	// ResetToken    string
	// TokenExpiry   time.Time
	// ApplicationID string
}
