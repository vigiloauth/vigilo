package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/mocks"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

const testToken string = "test_token"

func TestRegistrationService_RegisterUser(t *testing.T) {
	mockUserStore := &mocks.MockUserStore{}
	mockTokenService := &mocks.MockTokenManager{}

	mockUserStore.GetUserFunc = func(value string) *users.User { return nil }
	mockUserStore.AddUserFunc = func(user *users.User) error { return nil }
	mockTokenService.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) { return testToken, nil }

	userRegistration := NewRegistrationService(mockUserStore, mockTokenService)
	registeredUser, err := userRegistration.RegisterUser(createNewUser())

	assert.NoError(t, err)
	assert.NotNil(t, registeredUser)
}

func TestRegistrationService_DuplicateEntry(t *testing.T) {
	mockUserStore := &mocks.MockUserStore{}
	mockTokenService := &mocks.MockTokenManager{}
	user := createNewUser()

	mockUserStore.AddUserFunc = func(user *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(email string) *users.User { return user }

	userRegistration := NewRegistrationService(mockUserStore, mockTokenService)

	expected := errors.NewDuplicateUserError("email")
	_, actual := userRegistration.RegisterUser(user)

	assert.Error(t, actual)
	assert.Equal(t, actual, expected)
}

func TestRegistrationService_PasswordIsNotStoredInPlainText(t *testing.T) {
	mockUserStore := &mocks.MockUserStore{}
	mockTokenService := &mocks.MockTokenManager{}

	mockUserStore.DeleteUserFunc = func(email string) error { return nil }
	mockUserStore.AddUserFunc = func(user *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(email string) *users.User { return nil }
	mockTokenService.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) { return testToken, nil }

	userRegistration := NewRegistrationService(mockUserStore, mockTokenService)

	user := createNewUser()
	_, err := userRegistration.RegisterUser(user)
	assert.NoError(t, err)

	mockUserStore.GetUserFunc = func(email string) *users.User { return user }
	retrievedUser := mockUserStore.GetUserFunc(utils.TestConstants.Email)
	assert.NotEqual(t, retrievedUser.Password, utils.TestConstants.Password)
}

func TestUserRegistrationRequest_Validate(t *testing.T) {
	configurePasswordPolicy()
	tests := []struct {
		name      string
		req       *users.UserRegistrationRequest
		wantError bool
	}{
		{
			name:      "Validate returns no errors",
			req:       users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password),
			wantError: false,
		},
		{
			name:      "Validate returns error for empty username",
			req:       users.NewUserRegistrationRequest("", utils.TestConstants.Email, utils.TestConstants.Password),
			wantError: true,
		},
		{
			name:      "Validate returns error for empty email",
			req:       users.NewUserRegistrationRequest(utils.TestConstants.Username, "", utils.TestConstants.Password),
			wantError: true,
		},
		{
			name:      "Validate returns error for empty password",
			req:       users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, ""),
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
		req       *users.UserRegistrationRequest
		wantError bool
	}{
		{
			name:      "Validate returns an error when the password is missing an uppercase",
			req:       users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is missing a number",
			req:       users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is too short",
			req:       users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is missing a symbol",
			req:       users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
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

func createNewUser() *users.User {
	return users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
}

func configurePasswordPolicy() {
	pc := config.NewPasswordConfig(
		config.WithUppercase(),
		config.WithNumber(),
		config.WithSymbol(),
		config.WithMinLength(10),
	)
	config.NewServerConfig(
		config.WithPasswordConfig(pc),
	)
}
