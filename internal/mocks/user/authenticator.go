package mocks

import (
	"context"

	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

var _ users.UserAuthenticator = (*MockUserAuthenticator)(nil)

type MockUserAuthenticator struct {
	AuthenticateUserFunc func(ctx context.Context, request *users.UserLoginRequest) (*users.UserLoginResponse, error)
}

func (m *MockUserAuthenticator) AuthenticateUser(ctx context.Context, request *users.UserLoginRequest) (*users.UserLoginResponse, error) {
	return m.AuthenticateUserFunc(ctx, request)
}
