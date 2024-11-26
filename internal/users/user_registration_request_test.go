package users

import (
	"github.com/vigiloauth/vigilo/identity/config"
	"testing"
)

func TestUserRegistrationRequest_Validate(t *testing.T) {
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
