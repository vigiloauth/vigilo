package users

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func setupUserRegistration(t *testing.T) (*UserRegistration, UserStore) {
	ResetInMemoryUserStore()
	userStore := GetInMemoryUserStore()
	jwtConfig := config.NewJWTConfig()
	tokenService := token.NewTokenService(jwtConfig)
	userRegistration := NewUserRegistration(userStore, jwtConfig, tokenService)

	t.Cleanup(func() {
		ResetInMemoryUserStore()
	})

	return userRegistration, userStore
}

func TestUserRegistration_RegisterUser(t *testing.T) {
	userRegistration, _ := setupUserRegistration(t)
	registeredUser, err := userRegistration.Register(NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password))

	if err != nil {
		t.Errorf("RegisterUser() error = %v, wantError = %v", err, false)
	}

	assert.NotNil(t, registeredUser)
}

func TestUserRegistration_DuplicateEntry(t *testing.T) {
	userRegistration, userStore := setupUserRegistration(t)

	user := NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	_ = userStore.AddUser(user)

	_, err := userRegistration.Register(user)
	assert.NotNil(t, err)
}

func TestUserRegistration_PasswordIsNotStoredInPlainText(t *testing.T) {
	userRegistration, userStore := setupUserRegistration(t)

	_ = userStore.DeleteUser(utils.TestConstants.Email)

	user := NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	_, err := userRegistration.Register(user)
	assert.Nil(t, err)

	retrievedUser, _ := GetInMemoryUserStore().GetUser(utils.TestConstants.Email)
	assert.NotEqual(t, retrievedUser.Password, utils.TestConstants.Password)
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
			req:       NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password),
			wantError: false,
		},
		{
			name:      "Validate returns error for empty username",
			req:       NewUserRegistrationRequest("", utils.TestConstants.Email, utils.TestConstants.Password),
			wantError: true,
		},
		{
			name:      "Validate returns error for empty email",
			req:       NewUserRegistrationRequest(utils.TestConstants.Username, "", utils.TestConstants.Password),
			wantError: true,
		},
		{
			name:      "Validate returns error for empty password",
			req:       NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, ""),
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
			req:       NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is missing a number",
			req:       NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is too short",
			req:       NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is missing a symbol",
			req:       NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
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
	config.GetPasswordConfiguration().ConfigurePasswordPolicy(
		config.WithUppercase(),
		config.WithNumber(),
		config.WithSymbol(),
		config.WithMinLength(10),
	)
}
