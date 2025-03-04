package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/security"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func setupUserLogin(t *testing.T) (*UserLogin, users.UserStore) {
	users.ResetInMemoryUserStore()
	userStore := users.GetInMemoryUserStore()
	config := config.NewServerConfig()
	userLogin := NewUserLogin(userStore, NewLoginAttemptStore(), config)

	t.Cleanup(func() {
		users.ResetInMemoryUserStore()
	})

	return userLogin, userStore
}

func TestUserLogin_Successful(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := security.HashPassword(utils.TestConstants.Password)
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.Password
	loginAttempt := NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)
	_, err := userLogin.Login(user, loginAttempt)
	if err != nil {
		t.Errorf("LoginUser() error = %v, want nil", err)
	}
}

func TestUserLogin_Login(t *testing.T) {
	tests := []struct {
		name      string
		user      *users.User
		wantError bool
	}{
		{
			name:      "Login fails with invalid password",
			user:      users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Login fails when user is not found",
			user:      users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userLogin, userStore := setupUserLogin(t)
			if tt.name == "Login fails with invalid password" {
				encryptedPassword, _ := security.HashPassword(utils.TestConstants.Password)
				user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
				_ = userStore.AddUser(user)
			}

			loginAttempt := NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)
			_, err := userLogin.Login(tt.user, loginAttempt)

			if (err != nil) != tt.wantError {
				t.Errorf("Login() error = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}

func TestUserLogin_FailedAttempts(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := security.HashPassword(utils.TestConstants.Password)
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	for range 5 {
		_, err := userLogin.Login(user, loginAttempt)
		assert.NotNil(t, err)
	}

	attempts := userLogin.loginAttemptStore.GetLoginAttempts(user.ID)
	assert.Equal(t, 5, len(attempts))
}

func TestUserLogin_ArtificialDelay(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := security.HashPassword(utils.TestConstants.Password)
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	startTime := time.Now()
	_, err := userLogin.Login(user, loginAttempt)
	duration := time.Since(startTime)

	assert.NotNil(t, err)
	assert.GreaterOrEqual(t, duration, 500*time.Millisecond, "Expected artificial delay of at least 500ms")
}

func TestUserLogin_AccountLocking(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := security.HashPassword(utils.TestConstants.Password)
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = utils.TestConstants.InvalidPassword
	loginAttempt := NewLoginAttempt(utils.TestConstants.IPAddress, utils.TestConstants.RequestMetadata, utils.TestConstants.Details, utils.TestConstants.UserAgent)

	for range userLogin.maxFailedAttempts {
		_, err := userLogin.Login(user, loginAttempt)
		assert.NotNil(t, err)
	}

	retrievedUser, _ := userStore.GetUser(user.Email)
	assert.True(t, retrievedUser.AccountLocked, "Expected account to be locked")

	_, err := userLogin.Login(user, loginAttempt)
	assert.NotNil(t, err, "Expected error on login attempt with locked account")
	assert.IsType(t, &errors.AuthenticationError{}, err)
	assert.Equal(t, errors.ErrCodeAccountLocked, err.(*errors.AuthenticationError).ErrorCode)
}
