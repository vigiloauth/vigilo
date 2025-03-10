package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func setupRegistrationService(t *testing.T) (*RegistrationService, users.UserStore) {
	users.ResetInMemoryUserStore()
	userStore := users.GetInMemoryUserStore()
	tokenService := token.NewTokenService(token.GetInMemoryTokenStore())
	userRegistration := NewRegistrationService(userStore, tokenService)

	t.Cleanup(func() {
		users.ResetInMemoryUserStore()
	})

	return userRegistration, userStore
}

func TestRegistrationService_RegisterUser(t *testing.T) {
	userRegistration, _ := setupRegistrationService(t)
	registeredUser, err := userRegistration.RegisterUser(users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password))

	if err != nil {
		t.Errorf("RegisterUser() error = %v, wantError = %v", err, false)
	}

	assert.NotNil(t, registeredUser)
}

func TestRegistrationService_DuplicateEntry(t *testing.T) {
	userRegistration, userStore := setupRegistrationService(t)

	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	_ = userStore.AddUser(user)

	_, err := userRegistration.RegisterUser(user)
	assert.NotNil(t, err)
}

func TestRegistrationService_PasswordIsNotStoredInPlainText(t *testing.T) {
	userRegistration, userStore := setupRegistrationService(t)

	_ = userStore.DeleteUser(utils.TestConstants.Email)

	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	_, err := userRegistration.RegisterUser(user)
	assert.Nil(t, err)

	retrievedUser, _ := users.GetInMemoryUserStore().GetUser(utils.TestConstants.Email)
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
