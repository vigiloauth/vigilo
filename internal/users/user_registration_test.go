package users

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
)

func TestUserRegistration_RegisterUser(t *testing.T) {
	ResetInMemoryUserStore()
	userStore := GetInMemoryUserStore()
	userRegistration := NewUserRegistration(userStore)
	registeredUser, err := userRegistration.RegisterUser(NewUser(TestConstants.Username, TestConstants.Email, TestConstants.Password))

	if err != nil {
		t.Errorf("RegisterUser() error = %v, wantError = %v", err, false)
	}

	assert.NotNil(t, registeredUser)
}

func TestUserRegistration_DuplicateEntry(t *testing.T) {
	ResetInMemoryUserStore()
	userStore := GetInMemoryUserStore()
	userRegistration := NewUserRegistration(userStore)

	user := NewUser(TestConstants.Username, TestConstants.Email, TestConstants.Password)
	_ = userStore.AddUser(user)

	_, err := userRegistration.RegisterUser(user)
	assert.NotNil(t, err)
}

func TestUserRegistration_PasswordIsNotStoredInPlainText(t *testing.T) {
	ResetInMemoryUserStore()
	userStore := GetInMemoryUserStore()
	userRegistration := NewUserRegistration(userStore)
	_ = userStore.DeleteUser(TestConstants.Email)

	user := NewUser(TestConstants.Username, TestConstants.Email, TestConstants.Password)
	_, err := userRegistration.RegisterUser(user)
	assert.Nil(t, err)

	retrievedUser, _ := GetInMemoryUserStore().GetUser(TestConstants.Email)
	assert.NotEqual(t, retrievedUser.Password, TestConstants.Password)
}

func TestUserRegistrationRequest_Validate(t *testing.T) {
	configurePasswordPolicy()
	tests := []struct {
		name      string
		req       *UserRegistrationRequest
		wantError bool
	}{
		{
			name:      "Validate returns no errors",
			req:       NewUserRegistrationRequest(TestConstants.Username, TestConstants.Email, TestConstants.Password),
			wantError: false,
		},
		{
			name:      "Validate returns error for empty username",
			req:       NewUserRegistrationRequest("", TestConstants.Email, TestConstants.Password),
			wantError: true,
		},
		{
			name:      "Validate returns error for empty email",
			req:       NewUserRegistrationRequest(TestConstants.Username, "", TestConstants.Password),
			wantError: true,
		},
		{
			name:      "Validate returns error for empty password",
			req:       NewUserRegistrationRequest(TestConstants.Username, TestConstants.Email, ""),
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.req.Validate()
			if (err != nil) != test.wantError {
				t.Errorf("UserRegistrationRequest.Validate() error = %v, wantErr %v", err, test.wantError)
			}
		})
	}
}

func TestUserRegistrationRequest_InvalidPasswordFormat(t *testing.T) {
	configurePasswordPolicy()
	tests := []struct {
		name      string
		req       *UserRegistrationRequest
		wantError bool
	}{
		{
			name:      "Validate returns an error when the password is missing an uppercase",
			req:       NewUserRegistrationRequest(TestConstants.Username, TestConstants.Email, TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is missing a number",
			req:       NewUserRegistrationRequest(TestConstants.Username, TestConstants.Email, TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is too short",
			req:       NewUserRegistrationRequest(TestConstants.Username, TestConstants.Email, TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is missing a symbol",
			req:       NewUserRegistrationRequest(TestConstants.Username, TestConstants.Email, TestConstants.InvalidPassword),
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.req.Validate()
			if (err != nil) != test.wantError {
				t.Errorf("UserRegistrationRequest.Validate() error = %v, wantErr %v", err, test.wantError)
			}
		})
	}
}

func configurePasswordPolicy() {
	config.GetPasswordConfiguration().
		SetRequireUppercase(true).
		SetRequireNumber(true).
		SetRequireSymbol(true).
		SetMinimumLength(10).
		Build()
}
