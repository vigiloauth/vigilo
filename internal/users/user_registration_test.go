package users

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	username       string = "testUsername"
	password       string = "testPassword"
	email          string = "testEmail@gmail.com"
	duplicateEmail string = "testDuplicate@gmail.com"
)

func TestUserRegistration_RegisterUser(t *testing.T) {
	tests := []struct {
		name      string
		user      *User
		wantError bool
	}{
		{
			name:      "RegisterUser is successful",
			user:      &User{Username: username, Password: password, Email: email},
			wantError: false,
		},
		{
			name:      "RegisterUser fails with invalid email format",
			user:      &User{Username: username, Password: password, Email: "invalid@.com"},
			wantError: true,
		},
		{
			name:      "RegisterUser fails with invalid password length",
			user:      &User{Username: username, Password: "invalid", Email: email},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userRegistration := NewUserRegistration()
			registeredUser, err := userRegistration.RegisterUser(test.user)

			if (err != nil) != test.wantError {
				t.Errorf("RegisterUser() error = %v, wantError = %v", err, test.wantError)
				assert.Nil(t, registeredUser)
			}
		})
	}
}

func TestUserRegistration_DuplicateEntry(t *testing.T) {
	prepopulateCacheWithExistingUser()
	userRegistration := NewUserRegistration()
	_, err := userRegistration.RegisterUser(&User{Username: username, Password: password, Email: duplicateEmail})
	assert.NotNil(t, err)
}

func prepopulateCacheWithExistingUser() {
	_ = GetInMemoryUserStore().AddUser(User{
		ID:       "existing-user",
		Username: username,
		Email:    duplicateEmail,
		Password: password,
	})
}
