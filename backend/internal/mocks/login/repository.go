package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/login"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

var _ domain.LoginAttemptRepository = (*MockLoginAttemptRepository)(nil)

type MockLoginAttemptRepository struct {
	SaveLoginAttemptFunc         func(ctx context.Context, attempt *user.UserLoginAttempt) error
	GetLoginAttemptsByUserIDFunc func(ctx context.Context, userID string) ([]*user.UserLoginAttempt, error)
}

func (m *MockLoginAttemptRepository) SaveLoginAttempt(ctx context.Context, attempt *user.UserLoginAttempt) error {
	return m.SaveLoginAttemptFunc(ctx, attempt)
}

func (m *MockLoginAttemptRepository) GetLoginAttemptsByUserID(ctx context.Context, userID string) ([]*user.UserLoginAttempt, error) {
	return m.GetLoginAttemptsByUserIDFunc(ctx, userID)
}
