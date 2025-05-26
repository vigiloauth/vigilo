package mocks

import (
	"context"

	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

var _ users.UserCreator = (*MockUserCreator)(nil)

type MockUserCreator struct {
	CreateUserFunc func(ctx context.Context, user *users.User) (*users.UserRegistrationResponse, error)
}

func (m *MockUserCreator) CreateUser(ctx context.Context, user *users.User) (*users.UserRegistrationResponse, error) {
	return m.CreateUserFunc(ctx, user)
}
