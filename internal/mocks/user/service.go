package mocks

import user "github.com/vigiloauth/vigilo/internal/domain/user"

type MockUserService struct {
	CreateUserFunc       func(user *user.User) (*user.UserRegistrationResponse, error)
	AuthenticateUserFunc func(loginUser *user.User, attempt *user.UserLoginAttempt) (*user.UserLoginResponse, error)
	GetUserByIDFunc      func(userID string) *user.User
}

func (m *MockUserService) CreateUser(user *user.User) (*user.UserRegistrationResponse, error) {
	return m.CreateUserFunc(user)
}

func (m *MockUserService) AuthenticateUser(loginUser *user.User, attempt *user.UserLoginAttempt) (*user.UserLoginResponse, error) {
	return m.AuthenticateUserFunc(loginUser, attempt)
}

func (m *MockUserService) GetUserByID(userID string) *user.User {
	return m.GetUserByIDFunc(userID)
}
