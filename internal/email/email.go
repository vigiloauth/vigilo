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
}
