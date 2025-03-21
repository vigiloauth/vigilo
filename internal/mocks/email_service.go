package mocks

import (
	"time"

	"github.com/vigiloauth/vigilo/internal/email"
)

// MockEmailService is a mock implementation of the email.EmailService interface.
type MockEmailService struct {
	// SendEmailFunc is a mock function for the SendEmail method.
	SendEmailFunc func(request email.EmailRequest) error

	// GenerateEmailFunc is a mock function for the GenerateEmail method.
	GenerateEmailRequestFunc func(request email.EmailRequest) *email.EmailRequest

	// SetTemplateFunc is a mock function for the SetTemplate method.
	SetTemplateFunc func(template string) error

	// TestConnectionFunc is a mock function for the TestConnection method.
	TestConnectionFunc func() error

	// ProcessQueueFunc is a mock function for the ProcessQueue method.
	ProcessQueueFunc func()

	// StartQueueProcessorFunc is a mock function for the StartQueueProcessor method.
	StartQueueProcessorFunc func(interval time.Duration)

	// GetQueueStatusFunc is a mock function for the GetQueueStatus method.
	GetQueueStatusFunc func() (int, map[string]int)

	// ClearQueueFunc is a mock function for the ClearQueue method.
	ClearQueueFunc func()

	// GetDefaultTemplateFunc is a mock function for the GetDefaultTemplate method.
	GetDefaultTemplateFunc func() string

	// ShouldRetryEmailFunc is a mock function for the ShouldRetryEmail method.
	ShouldRetryEmailFunc func(now time.Time, request email.EmailRequest) bool
}

// SendEmail calls the mock SendEmailFunc.
func (m *MockEmailService) SendEmail(request email.EmailRequest) error {
	return m.SendEmailFunc(request)
}

// GenerateEmail calls the mock GenerateEmailFunc.
func (m *MockEmailService) GenerateEmailRequest(request email.EmailRequest) *email.EmailRequest {
	return m.GenerateEmailRequestFunc(request)
}

// SetTemplate calls the mock SetTemplateFunc.
func (m *MockEmailService) SetTemplate(template string) error {
	return m.SetTemplateFunc(template)
}

// TestConnection calls the mock TestConnectionFunc.
func (m *MockEmailService) TestConnection() error {
	return m.TestConnectionFunc()
}

// ProcessQueue calls the mock ProcessQueueFunc.
func (m *MockEmailService) ProcessQueue() {
	m.ProcessQueueFunc()
}

// StartQueueProcessor calls the mock StartQueueProcessorFunc.
func (m *MockEmailService) StartQueueProcessor(interval time.Duration) {
	m.StartQueueProcessorFunc(interval)
}

// GetQueueStatus calls the mock GetQueueStatusFunc.
func (m *MockEmailService) GetQueueStatus() (int, map[string]int) {
	return m.GetQueueStatusFunc()
}

// ClearQueue calls the mock ClearQueueFunc.
func (m *MockEmailService) ClearQueue() {
	m.ClearQueueFunc()
}
