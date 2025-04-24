package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/internal/domain/email"
)

var _ domain.EmailService = (*MockEmailService)(nil)

type MockEmailService struct {
	SendEmailFunc          func(ctx context.Context, request *domain.EmailRequest) error
	TestConnectionFunc     func() error
	GetEmailRetryQueueFunc func() *domain.EmailRetryQueue
}

func (m *MockEmailService) SendEmail(ctx context.Context, request *domain.EmailRequest) error {
	return m.SendEmailFunc(ctx, request)
}

func (m *MockEmailService) TestConnection() error {
	return m.TestConnectionFunc()
}

func (m *MockEmailService) GetEmailRetryQueue() *domain.EmailRetryQueue {
	return m.GetEmailRetryQueueFunc()
}
