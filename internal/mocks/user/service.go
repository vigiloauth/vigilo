package mocks

import (
	"context"

	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

var _ user.UserService = (*MockUserService)(nil)

type MockUserService struct {
	CreateUserFunc                  func(ctx context.Context, user *user.User) (*user.UserRegistrationResponse, error)
	HandleOAuthLoginFunc            func(ctx context.Context, request *user.UserLoginRequest, clientID, redirectURI string) (*user.UserLoginResponse, error)
	AuthenticateUserWithRequestFunc func(ctx context.Context, request *user.UserLoginRequest) (*user.UserLoginResponse, error)
	GetUserByIDFunc                 func(ctx context.Context, userID string) (*user.User, error)
	GetUserByUsernameFunc           func(ctx context.Context, username string) (*user.User, error)
	ValidateVerificationCodeFunc    func(ctx context.Context, verificationCode string) error
	DeleteUnverifiedUsersFunc       func(ctx context.Context) error
	ResetPasswordFunc               func(ctx context.Context, userEmail, newPassword, resetToken string) (*user.UserPasswordResetResponse, error)
}

func (m *MockUserService) CreateUser(ctx context.Context, user *user.User) (*user.UserRegistrationResponse, error) {
	return m.CreateUserFunc(ctx, user)
}

func (m *MockUserService) AuthenticateUser(ctx context.Context, request *user.UserLoginRequest, clientID, redirectURI string) (*user.UserLoginResponse, error) {
	return m.HandleOAuthLoginFunc(ctx, request, clientID, redirectURI)
}

func (m *MockUserService) AuthenticateUserWithRequest(ctx context.Context, request *user.UserLoginRequest) (*user.UserLoginResponse, error) {
	return m.AuthenticateUserWithRequestFunc(ctx, request)
}

func (m *MockUserService) GetUserByID(ctx context.Context, userID string) (*user.User, error) {
	return m.GetUserByIDFunc(ctx, userID)
}

func (m *MockUserService) GetUserByUsername(ctx context.Context, username string) (*user.User, error) {
	return m.GetUserByUsernameFunc(ctx, username)
}

func (m *MockUserService) ValidateVerificationCode(ctx context.Context, verificationCode string) error {
	return m.ValidateVerificationCodeFunc(ctx, verificationCode)
}

func (m *MockUserService) DeleteUnverifiedUsers(ctx context.Context) error {
	return m.DeleteUnverifiedUsersFunc(ctx)
}

func (m *MockUserService) ResetPassword(ctx context.Context, userEmail, newPassword, resetToken string) (*user.UserPasswordResetResponse, error) {
	return m.ResetPasswordFunc(ctx, userEmail, newPassword, resetToken)
}
