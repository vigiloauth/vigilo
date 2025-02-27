package users

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/security"
)

func setupUserLogin(t *testing.T) (*UserLogin, UserStore) {
	ResetInMemoryUserStore()
	userStore := GetInMemoryUserStore()
	config := config.NewDefaultServerConfig()
	userLogin := NewUserLogin(userStore, NewLoginAttemptStore(), config)

	t.Cleanup(func() {
		ResetInMemoryUserStore()
	})

	return userLogin, userStore
}

func TestUserLogin_Successful(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := security.HashPassword(TestConstants.Password)
	user := NewUser(TestConstants.Username, TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = TestConstants.Password
	loginAttempt := NewLoginAttempt(TestConstants.IPAddress, TestConstants.RequestMetadata, TestConstants.Details, TestConstants.UserAgent)
	_, err := userLogin.Login(user, loginAttempt)
	if err != nil {
		t.Errorf("LoginUser() error = %v, want nil", err)
	}
}

func TestUserLogin_Login(t *testing.T) {
	tests := []struct {
		name      string
		user      *User
		wantError bool
	}{
		{
			name:      "Login fails with invalid password",
			user:      NewUser(TestConstants.Username, TestConstants.Email, TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Login fails when user is not found",
			user:      NewUser(TestConstants.Username, TestConstants.Email, TestConstants.Password),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userLogin, userStore := setupUserLogin(t)
			if tt.name == "Login fails with invalid password" {
				encryptedPassword, _ := security.HashPassword(TestConstants.Password)
				user := NewUser(TestConstants.Username, TestConstants.Email, encryptedPassword)
				_ = userStore.AddUser(user)
			}

			loginAttempt := NewLoginAttempt(TestConstants.IPAddress, TestConstants.RequestMetadata, TestConstants.Details, TestConstants.UserAgent)
			_, err := userLogin.Login(tt.user, loginAttempt)

			if (err != nil) != tt.wantError {
				t.Errorf("Login() error = %v, wantError = %v", err, tt.wantError)
			}
		})
	}
}

func TestUserLogin_FailedAttempts(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := security.HashPassword(TestConstants.Password)
	user := NewUser(TestConstants.Username, TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = TestConstants.InvalidPassword
	loginAttempt := NewLoginAttempt(TestConstants.IPAddress, TestConstants.RequestMetadata, TestConstants.Details, TestConstants.UserAgent)

	for range 5 {
		_, err := userLogin.Login(user, loginAttempt)
		assert.NotNil(t, err)
	}

	attempts := userLogin.loginAttemptStore.GetLoginAttempts(user.ID)
	assert.Equal(t, 5, len(attempts))
}

func TestUserLogin_ArtificialDelay(t *testing.T) {
	userLogin, userStore := setupUserLogin(t)
	encryptedPassword, _ := security.HashPassword(TestConstants.Password)
	user := NewUser(TestConstants.Username, TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = TestConstants.InvalidPassword
	loginAttempt := NewLoginAttempt(TestConstants.IPAddress, TestConstants.RequestMetadata, TestConstants.Details, TestConstants.UserAgent)

	startTime := time.Now()
	_, err := userLogin.Login(user, loginAttempt)
	duration := time.Since(startTime)

	assert.NotNil(t, err)
	assert.GreaterOrEqual(t, duration, 500*time.Millisecond, "Expected artificial delay of at least 500ms")
}
