package domain

type EmailService interface {
	SendEmail(request *EmailRequest) error
	TestConnection() error
	GetEmailRetryQueue() *EmailRetryQueue
}
