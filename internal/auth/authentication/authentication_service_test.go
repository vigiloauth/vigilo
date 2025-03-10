package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	loginAttempt "github.com/vigiloauth/vigilo/internal/auth/loginattempt"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func setupAuthenticationService(t *testing.T) (*AuthenticationService, users.UserStore) {
	users.ResetInMemoryUserStore()
	config.NewServerConfig()

	userStore := users.GetInMemoryUserStore()
	loginAttemptStore := loginAttempt.NewLoginAttemptStore()
	tokenService := token.NewTokenService(token.GetInMemoryTokenStore())

	userLogin := NewAuthenticationService(userStore, loginAttemptStore, tokenService)

	t.Cleanup(func() {
		users.ResetInMemoryUserStore()
	})

	return userLogin, userStore
}

func TestAuthenticationService_SuccessfulUserAuthentication(t *testing.T) {
	userLogin, userStore := setupAuthenticationService(t)
	encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.Password
	loginAttempt := loginAttempt.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	_, err := userLogin.AuthenticateUser(user, loginAttempt)
	assert.NoError(t, err, "unexpected error during login")
}

func TestAuthenticationService_AuthenticateUser(t *testing.T) {
	tests := []struct {
		name      string
		user      *users.User
		wantError bool
	}{
		{
			name:      "User authentication fails with invalid password",
			user:      users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "User authentication fails when user is not found",
			user:      users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userLogin, userStore := setupAuthenticationService(t)
			if tt.name == "User authentication fails with invalid password" {
				encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
				user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
				_ = userStore.AddUser(user)
			}

			loginAttempt := loginAttempt.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)
			_, err := userLogin.AuthenticateUser(tt.user, loginAttempt)

			if (err != nil) != tt.wantError {
				t.Errorf("AuthenticateUser() error = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}

func TestAuthenticationService_FailedUserAuthenticationAttempts(t *testing.T) {
	userLogin, userStore := setupAuthenticationService(t)
	encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := loginAttempt.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	loginAttempts := 5
	for range loginAttempts {
		_, err := userLogin.AuthenticateUser(user, loginAttempt)
		assert.NotNil(t, err)
	}

	attempts := userLogin.loginAttemptStore.GetLoginAttempts(user.ID)
	assert.Equal(t, loginAttempts, len(attempts))
}

func TestAuthenticationService_ArtificialDelayDuringUserAuthentication(t *testing.T) {
	userLogin, userStore := setupAuthenticationService(t)
	encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := loginAttempt.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	startTime := time.Now()
	_, err := userLogin.AuthenticateUser(user, loginAttempt)
	duration := time.Since(startTime)

	assert.NotNil(t, err)
	assert.GreaterOrEqual(t, duration, 500*time.Millisecond, "expected artificial delay of at least 500ms")
}

func TestAuthenticationService_AccountLockingDuringUserAuthentication(t *testing.T) {
	userLogin, userStore := setupAuthenticationService(t)
	encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := loginAttempt.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	for range userLogin.maxFailedAttempts {
		_, err := userLogin.AuthenticateUser(user, loginAttempt)
		assert.NotNil(t, err)
	}

	retrievedUser, _ := userStore.GetUser(user.Email)
	assert.True(t, retrievedUser.AccountLocked, "expected account to be locked")

	_, err := userLogin.AuthenticateUser(user, loginAttempt)
	assert.NotNil(t, err, "expected error on login attempt with locked account")
	assert.IsType(t, &errors.AuthenticationError{}, err)
	assert.Equal(t, errors.ErrCodeAccountLocked, err.(*errors.AuthenticationError).ErrorCode)
}
