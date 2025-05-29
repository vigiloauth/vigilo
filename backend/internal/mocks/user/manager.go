package mocks

import (
	"context"

	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

var _ users.UserManager = (*MockUserManager)(nil)

type MockUserManager struct {
	GetUserByUsernameFunc     func(ctx context.Context, username string) (*users.User, error)
	GetUserByIDFunc           func(ctx context.Context, userID string) (*users.User, error)
	DeleteUnverifiedUsersFunc func(ctx context.Context) error
	ResetPasswordFunc         func(ctx context.Context, userEmail, newPassword, resetToken string) (*users.UserPasswordResetResponse, error)
}

func (m *MockUserManager) GetUserByUsername(ctx context.Context, username string) (*users.User, error) {
	return m.GetUserByUsernameFunc(ctx, username)
}

func (m *MockUserManager) GetUserByID(ctx context.Context, userID string) (*users.User, error) {
	return m.GetUserByIDFunc(ctx, userID)
}

func (m *MockUserManager) DeleteUnverifiedUsers(ctx context.Context) error {
	return m.DeleteUnverifiedUsersFunc(ctx)
}

func (m *MockUserManager) ResetPassword(
	ctx context.Context,
	userEmail string,
	newPassword string,
	resetToken string,
) (*users.UserPasswordResetResponse, error) {
	return m.ResetPasswordFunc(ctx, userEmail, newPassword, resetToken)
}
