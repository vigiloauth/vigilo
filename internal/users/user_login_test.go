package users

import (
	"testing"

	"github.com/vigiloauth/vigilo/internal/security"
)

func TestUserLogin_Successful(t *testing.T) {
	ResetInMemoryUserStore()
	userStore := GetInMemoryUserStore()
	userLogin := NewUserLogin(userStore)
	encryptedPassword, _ := security.HashPassword(TestConstants.Password)
	user := NewUser(TestConstants.Username, TestConstants.Email, encryptedPassword)
	_ = userStore.AddUser(user)

	user.Password = TestConstants.Password
	_, err := userLogin.LoginUser(user)
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ResetInMemoryUserStore()
			userStore := GetInMemoryUserStore()
			userLogin := NewUserLogin(userStore)
			_, err := userLogin.LoginUser(test.user)

			if (err != nil) != test.wantError {
				t.Errorf("LoginUser() error = %v, wantError = %v", err, test.wantError)
			}
		})
	}
}
