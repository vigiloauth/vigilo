package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/internal/domain/login"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
)

var _ domain.LoginAttemptService = (*MockLoginAttemptService)(nil)

type MockLoginAttemptService struct {
	SaveLoginAttemptFunc         func(ctx context.Context, attempt *user.UserLoginAttempt) error
	GetLoginAttemptsByUserIDFunc func(ctx context.Context, userID string) ([]*user.UserLoginAttempt, error)
	HandleFailedLoginAttemptFunc func(ctx context.Context, user *user.User, attempt *user.UserLoginAttempt) error
}

func (m *MockLoginAttemptService) SaveLoginAttempt(ctx context.Context, attempt *user.UserLoginAttempt) error {
	return m.SaveLoginAttemptFunc(ctx, attempt)
}

func (m *MockLoginAttemptService) GetLoginAttemptsByUserID(ctx context.Context, userID string) ([]*user.UserLoginAttempt, error) {
	return m.GetLoginAttemptsByUserIDFunc(ctx, userID)
}

func (m *MockLoginAttemptService) HandleFailedLoginAttempt(ctx context.Context, user *user.User, attempt *user.UserLoginAttempt) error {
	return m.HandleFailedLoginAttemptFunc(ctx, user, attempt)
}
