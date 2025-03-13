package email

import "time"

type EmailService interface {
	SendEmail(request EmailRequest) error
	GenerateEmail(request EmailRequest) *EmailRequest
	SetTemplate(template string) error
	TestConnection() error
	ProcessQueue()
	StartQueueProcessor(interval time.Duration)
	GetQueueStatus() (int, map[string]int)
	ClearQueue()
}

const (
	TestSMTPServer        string = "localhost"
	TestSMTPPort          int    = 2525
	TestInvalidSMTPServer string = "invalid-smt-server.com"
	TestFromAddress       string = "no-reply@example.com"
	TestRecipient         string = "user@example.com"
	TestApplicationID     string = "TestApp"
)
