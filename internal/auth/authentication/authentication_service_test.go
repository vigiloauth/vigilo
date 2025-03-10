package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	login "github.com/vigiloauth/vigilo/internal/auth/loginattempt"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/mocks"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func TestAuthenticationService_SuccessfulUserAuthentication(t *testing.T) {
	mockUserStore := &mocks.MockUserStore{}
	mockLoginAttemptStore := &mocks.MockLoginAttemptStore{}
	mockTokenService := &mocks.MockTokenManager{}
	user := createTestUser(t)

	mockUserStore.AddUserFunc = func(u *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(email string) *users.User { return user }
	mockTokenService.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) { return "testToken", nil }
	mockLoginAttemptStore.SaveLoginAttemptFunc = func(attempt *login.LoginAttempt) {}
	mockUserStore.UpdateUserFunc = func(user *users.User) error { return nil }

	authService := NewAuthenticationService(mockUserStore, mockLoginAttemptStore, mockTokenService)
	loginUser := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	loginAttempt := createTestLoginAttempt()

	_, err := authService.AuthenticateUser(loginUser, loginAttempt)
	assert.NoError(t, err, "unexpected error during login")
}

func TestAuthenticationService_AuthenticateUserInvalidPassword(t *testing.T) {
	mockUserStore := &mocks.MockUserStore{}
	mockLoginAttemptStore := &mocks.MockLoginAttemptStore{}
	mockTokenService := &mocks.MockTokenManager{}
	user := createTestUser(t)

	mockUserStore.GetUserFunc = func(value string) *users.User { return user }
	mockLoginAttemptStore.SaveLoginAttemptFunc = func(attempt *login.LoginAttempt) {}
	mockUserStore.UpdateUserFunc = func(user *users.User) error { return nil }
	mockLoginAttemptStore.GetLoginAttemptsFunc = func(userID string) []*login.LoginAttempt {
		attempts := []*login.LoginAttempt{}
		attempts = append(attempts, &login.LoginAttempt{})
		return attempts
	}

	authService := NewAuthenticationService(mockUserStore, mockLoginAttemptStore, mockTokenService)
	loginUser := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, "password")
	loginAttempt := createTestLoginAttempt()

	expected := errors.NewInvalidCredentialsError()
	_, actual := authService.AuthenticateUser(loginUser, loginAttempt)

	assert.Error(t, actual, "expected error during authentication")
	assert.Equal(t, actual, expected)
}

func TestAuthenticationService_AuthenticateUser_UserNotFound(t *testing.T) {
	mockUserStore := &mocks.MockUserStore{}
	mockLoginAttemptStore := &mocks.MockLoginAttemptStore{}
	mockTokenService := &mocks.MockTokenManager{}

	mockUserStore.GetUserFunc = func(value string) *users.User { return nil }

	authService := NewAuthenticationService(mockUserStore, mockLoginAttemptStore, mockTokenService)
	loginUser := createTestUser(t)
	loginAttempt := createTestLoginAttempt()

	expected := errors.NewInvalidCredentialsError()
	_, actual := authService.AuthenticateUser(loginUser, loginAttempt)

	assert.Error(t, actual, "expected error during authentication")
	assert.Equal(t, actual, expected)
}

func TestAuthenticationService_FailedUserAuthenticationAttempts(t *testing.T) {
	mockUserStore := &mocks.MockUserStore{}
	mockLoginAttemptStore := &mocks.MockLoginAttemptStore{}
	mockTokenService := &mocks.MockTokenManager{}
	user := createTestUser(t)

	mockUserStore.AddUserFunc = func(u *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(value string) *users.User { return user }
	mockLoginAttemptStore.SaveLoginAttemptFunc = func(attempt *login.LoginAttempt) {}
	mockUserStore.UpdateUserFunc = func(user *users.User) error { return nil }
	mockLoginAttemptStore.SaveLoginAttemptFunc = func(attempt *login.LoginAttempt) {}
	mockLoginAttemptStore.GetLoginAttemptsFunc = func(userID string) []*login.LoginAttempt {
		attempts := []*login.LoginAttempt{}
		totalAttempts := 5
		for range totalAttempts {
			attempts = append(attempts, &login.LoginAttempt{})
		}
		return attempts
	}

	authService := NewAuthenticationService(mockUserStore, mockLoginAttemptStore, mockTokenService)
	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := createTestLoginAttempt()
	expectedAttempts := 5
	for range expectedAttempts {
		_, err := authService.AuthenticateUser(user, loginAttempt)
		assert.NotNil(t, err, "expected error to not be nil during authentication")
	}

	attempts := authService.loginAttemptStore.GetLoginAttempts(user.ID)
	assert.Equal(t, len(attempts), expectedAttempts)
}

func TestAuthenticationService_ArtificialDelayDuringUserAuthentication(t *testing.T) {
	mockUserStore := &mocks.MockUserStore{}
	mockLoginAttemptStore := &mocks.MockLoginAttemptStore{}
	mockTokenService := &mocks.MockTokenManager{}
	user := createTestUser(t)

	mockUserStore.AddUserFunc = func(u *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(email string) *users.User { return user }
	mockLoginAttemptStore.SaveLoginAttemptFunc = func(attempt *login.LoginAttempt) {}
	mockUserStore.UpdateUserFunc = func(user *users.User) error { return nil }
	mockLoginAttemptStore.GetLoginAttemptsFunc = func(userID string) []*login.LoginAttempt { return []*login.LoginAttempt{} }

	authService := NewAuthenticationService(mockUserStore, mockLoginAttemptStore, mockTokenService)
	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := login.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	expected := 500 * time.Millisecond
	startTime := time.Now()
	_, err := authService.AuthenticateUser(user, loginAttempt)
	actual := time.Since(startTime)

	assert.NotNil(t, err)
	assert.GreaterOrEqual(t, actual, expected, "expected artificial delay of at least 500ms")
}

func TestAuthenticationService_AccountLockingDuringUserAuthentication(t *testing.T) {
	mockUserStore := &mocks.MockUserStore{}
	mockLoginAttemptStore := &mocks.MockLoginAttemptStore{}
	mockTokenService := &mocks.MockTokenManager{}
	user := createTestUser(t)

	mockUserStore.AddUserFunc = func(u *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(value string) *users.User { return user }
	mockLoginAttemptStore.SaveLoginAttemptFunc = func(attempt *login.LoginAttempt) {}
	mockUserStore.UpdateUserFunc = func(user *users.User) error { return nil }
	mockLoginAttemptStore.SaveLoginAttemptFunc = func(attempt *login.LoginAttempt) {}
	mockLoginAttemptStore.GetLoginAttemptsFunc = func(userID string) []*login.LoginAttempt {
		attempts := []*login.LoginAttempt{}
		totalAttempts := 5
		for range totalAttempts {
			attempts = append(attempts, &login.LoginAttempt{})
		}
		return attempts
	}

	authService := NewAuthenticationService(mockUserStore, mockLoginAttemptStore, mockTokenService)
	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := createTestLoginAttempt()
	for range authService.maxFailedAttempts {
		_, err := authService.AuthenticateUser(user, loginAttempt)
		assert.NotNil(t, err)
	}

	retrievedUser := mockUserStore.GetUserFunc(utils.TestConstants.Email)
	assert.True(t, retrievedUser.AccountLocked, "expected account to be locked")

	expected := errors.NewAccountLockedError()
	_, actual := authService.AuthenticateUser(user, loginAttempt)

	assert.NotNil(t, actual, "expected error on login attempt with locked account")
	assert.Equal(t, actual, expected)
}

func createTestUser(t *testing.T) *users.User {
	encryptedPassword, err := utils.HashPassword(utils.TestConstants.Password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	return users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
}

func createTestLoginAttempt() *login.LoginAttempt {
	return login.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)
}
