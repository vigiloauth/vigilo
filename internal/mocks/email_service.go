package mocks

import (
	"time"

	"github.com/vigiloauth/vigilo/internal/email"
)

type MockEmailService struct {
	SendEmailFunc           func(request email.EmailRequest) error
	GenerateEmailFunc       func(request email.EmailRequest) *email.EmailRequest
	SetTemplateFunc         func(template string) error
	TestConnectionFunc      func() error
	ProcessQueueFunc        func()
	StartQueueProcessorFunc func(interval time.Duration)
	GetQueueStatusFunc      func() (int, map[string]int)
}

func (m *MockEmailService) SendEmail(request email.EmailRequest) error {
	return m.SendEmailFunc(request)
}

func (m *MockEmailService) GenerateEmail(request email.EmailRequest) *email.EmailRequest {
	return m.GenerateEmailFunc(request)
}

func (m *MockEmailService) SetTemplate(template string) error {
	return m.SetTemplateFunc(template)
}

func (m *MockEmailService) TestConnection() error {
	return m.TestConnectionFunc()
}

func (m *MockEmailService) ProcessQueue() {
	m.ProcessQueueFunc()
}

func (m *MockEmailService) StartQueueProcessor(interval time.Duration) {
	m.StartQueueProcessorFunc(interval)
}

func (m *MockEmailService) GetQueueStatus() (int, map[string]int) {
	return m.GetQueueStatusFunc()
}
