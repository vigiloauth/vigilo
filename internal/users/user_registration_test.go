package users

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUserRegistration_RegisterUser(t *testing.T) {
	tests := []struct {
		name      string
		user      *User
		wantError bool
	}{
		{
			name:      "RegisterUser is successful",
			user:      NewUser(TestConstants.Username, TestConstants.Email, TestConstants.Password),
			wantError: false,
		},
		{
			name:      "RegisterUser fails with invalid password length",
			user:      NewUser(TestConstants.Username, TestConstants.Email, TestConstants.InvalidPassword),
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userStore := GetInMemoryUserStore()
			userRegistration := NewUserRegistration(userStore)
			registeredUser, err := userRegistration.RegisterUser(test.user)

			if (err != nil) != test.wantError {
				t.Errorf("RegisterUser() error = %v, wantError = %v", err, test.wantError)
				assert.Nil(t, registeredUser)
			}
		})
	}
}

func TestUserRegistration_DuplicateEntry(t *testing.T) {
	userStore := GetInMemoryUserStore()
	userRegistration := NewUserRegistration(userStore)

	user := NewUser(TestConstants.Username, TestConstants.Email, TestConstants.Password)
	_ = userStore.AddUser(*user)

	_, err := userRegistration.RegisterUser(user)
	assert.NotNil(t, err)
}

func TestUserRegistration_PasswordIsNotStoredInPlainText(t *testing.T) {
	userStore := GetInMemoryUserStore()
	userRegistration := NewUserRegistration(userStore)
	_ = userStore.DeleteUser(TestConstants.Email)

	user := NewUser(TestConstants.Username, TestConstants.Email, TestConstants.Password)
	_, err := userRegistration.RegisterUser(user)
	assert.Nil(t, err)

	retrievedUser, _ := GetInMemoryUserStore().GetUser(TestConstants.Email)
	assert.NotEqual(t, retrievedUser.Password, TestConstants.Password)
}
