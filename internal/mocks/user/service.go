package mocks

import user "github.com/vigiloauth/vigilo/internal/domain/user"

var _ user.UserService = (*MockUserService)(nil)

type MockUserService struct {
	CreateUserFunc                  func(user *user.User) (*user.UserRegistrationResponse, error)
	HandleOAuthLoginFunc            func(request *user.UserLoginRequest, clientID, redirectURI, remoteAddr, forwardedFor, userAgent string) (*user.UserLoginResponse, error)
	AuthenticateUserWithRequestFunc func(request *user.UserLoginRequest, remoteAddr, forwardedFor, userAgent string) (*user.UserLoginResponse, error)
	GetUserByIDFunc                 func(userID string) *user.User
	GetUserByUsernameFunc           func(username string) *user.User
	ValidateVerificationCodeFunc    func(verificationCode string) error
}

func (m *MockUserService) CreateUser(user *user.User) (*user.UserRegistrationResponse, error) {
	return m.CreateUserFunc(user)
}

func (m *MockUserService) HandleOAuthLogin(request *user.UserLoginRequest, clientID, redirectURI, remoteAddr, forwardedFor, userAgent string) (*user.UserLoginResponse, error) {
	return m.HandleOAuthLoginFunc(request, clientID, redirectURI, remoteAddr, forwardedFor, userAgent)
}

func (m *MockUserService) AuthenticateUserWithRequest(request *user.UserLoginRequest, remoteAddr, forwardedFor, userAgent string) (*user.UserLoginResponse, error) {
	return m.AuthenticateUserWithRequestFunc(request, remoteAddr, forwardedFor, userAgent)
}

func (m *MockUserService) GetUserByID(userID string) *user.User {
	return m.GetUserByIDFunc(userID)
}

func (m *MockUserService) GetUserByUsername(username string) *user.User {
	return m.GetUserByUsernameFunc(username)
}

func (m *MockUserService) ValidateVerificationCode(verificationCode string) error {
	return m.ValidateVerificationCodeFunc(verificationCode)
}
