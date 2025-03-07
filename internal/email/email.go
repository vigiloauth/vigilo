package email

import "time"

type EmailService interface {
	SendMail(request EmailRequest) error
	SetTemplate(template string) error
	TestConnection() error
	ProcessQueue()
	StartQueueProcessor(interval time.Duration)
	GetQueueStatus() (int, map[string]int)
}
