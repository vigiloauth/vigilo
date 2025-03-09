package users

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/auth"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func setupUserLogin(t *testing.T) (*UserLogin, UserStore) {
	ResetInMemoryUserStore()
	config.NewServerConfig()

	userStore := GetInMemoryUserStore()
	loginAttemptStore := auth.NewLoginAttemptStore()
	tokenService := token.NewTokenService()

	userLogin := NewUserLogin(userStore, loginAttemptStore, tokenService)

	t.Cleanup(func() {
		ResetInMemoryUserStore()
	})

	return userLogin, userStore
}

func TestUserLogin_Successful(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
	user := NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.Password
	loginAttempt := auth.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	_, err := userLogin.Login(user, loginAttempt)
	assert.NoError(t, err, "unexpected error during login")
}

func TestUserLogin_Login(t *testing.T) {
	tests := []struct {
		name      string
		user      *User
		wantError bool
	}{
		{
			name:      "Login fails with invalid password",
			user:      NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Login fails when user is not found",
			user:      NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userLogin, userStore := setupUserLogin(t)
			if tt.name == "Login fails with invalid password" {
				encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
				user := NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
				_ = userStore.AddUser(user)
			}

			loginAttempt := auth.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)
			_, err := userLogin.Login(tt.user, loginAttempt)

			if (err != nil) != tt.wantError {
				t.Errorf("Login() error = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}

func TestUserLogin_FailedAttempts(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
	user := NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := auth.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	loginAttempts := 5
	for range loginAttempts {
		_, err := userLogin.Login(user, loginAttempt)
		assert.NotNil(t, err)
	}

	attempts := userLogin.loginAttemptStore.GetLoginAttempts(user.ID)
	assert.Equal(t, loginAttempts, len(attempts))
}

func TestUserLogin_ArtificialDelay(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
	user := NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := auth.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	startTime := time.Now()
	_, err := userLogin.Login(user, loginAttempt)
	duration := time.Since(startTime)

	assert.NotNil(t, err)
	assert.GreaterOrEqual(t, duration, 500*time.Millisecond, "expected artificial delay of at least 500ms")
}

func TestUserLogin_AccountLocking(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := utils.HashPassword(utils.TestConstants.Password)
	user := NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := auth.NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	for range userLogin.maxFailedAttempts {
		_, err := userLogin.Login(user, loginAttempt)
		assert.NotNil(t, err)
	}

	retrievedUser, _ := userStore.GetUser(user.Email)
	assert.True(t, retrievedUser.AccountLocked, "expected account to be locked")

	_, err := userLogin.Login(user, loginAttempt)
	assert.NotNil(t, err, "expected error on login attempt with locked account")
	assert.IsType(t, &errors.AuthenticationError{}, err)
	assert.Equal(t, errors.ErrCodeAccountLocked, err.(*errors.AuthenticationError).ErrorCode)
}
