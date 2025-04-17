package service

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/crypto"
	clients "github.com/vigiloauth/vigilo/internal/domain/client"
	email "github.com/vigiloauth/vigilo/internal/domain/email"
	tokens "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	mEmailService "github.com/vigiloauth/vigilo/internal/mocks/email"
	mLoginService "github.com/vigiloauth/vigilo/internal/mocks/login"
	mTokenService "github.com/vigiloauth/vigilo/internal/mocks/token"
	mUserRepo "github.com/vigiloauth/vigilo/internal/mocks/user"
)

const (
	testUsername         string = "username"
	testEmail            string = "test@mail.com"
	testToken            string = "test_token"
	testUserID           string = "user_id"
	testPassword1        string = "pas$_W0Rdssss"
	testPassword2        string = "PAs%$_W0Rddd"
	testInvalidPassword  string = "invalid"
	testIPAddress        string = "127.001.00"
	testRequestMetadata  string = "request_metadata"
	testUserAgent        string = "user_agent"
	testRequestDetails   string = "request_details"
	testVerificationCode string = "12345"
)

func TestUserService_CreateUser_Success(t *testing.T) {
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockTokenService := &mTokenService.MockTokenService{}
	mockLoginService := &mLoginService.MockLoginAttemptService{}
	mockEmailService := &mEmailService.MockEmailService{}

	mockUserRepo.GetUserByEmailFunc = func(email string) *users.User { return nil }
	mockUserRepo.AddUserFunc = func(user *users.User) error { return nil }
	mockTokenService.GenerateTokenFunc = func(subject, scope string, expirationTime time.Duration) (string, error) { return testToken, nil }
	mockEmailService.SendEmailFunc = func(request *email.EmailRequest) error { return nil }

	userService := NewUserService(mockUserRepo, mockTokenService, mockLoginService, mockEmailService)
	registeredUser, err := userService.CreateUser(createNewUser())

	assert.NoError(t, err)
	assert.NotNil(t, registeredUser)
}

func TestUserService_CreateUser_DuplicateEntry(t *testing.T) {
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockTokenService := &mTokenService.MockTokenService{}
	mockLoginService := &mLoginService.MockLoginAttemptService{}

	user := createNewUser()

	mockUserRepo.AddUserFunc = func(user *users.User) error { return nil }
	mockUserRepo.GetUserByEmailFunc = func(email string) *users.User { return user }

	userService := NewUserService(mockUserRepo, mockTokenService, mockLoginService, nil)

	expected := errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided email")
	_, actual := userService.CreateUser(user)

	assert.Error(t, actual)
	assert.Equal(t, actual, expected)
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
			req:       users.NewUserRegistrationRequest(testUsername, testEmail, testPassword1),
			wantError: false,
		},
		{
			name:      "Validate returns error for empty username",
			req:       users.NewUserRegistrationRequest("", testEmail, testPassword1),
			wantError: true,
		},
		{
			name:      "Validate returns error for empty email",
			req:       users.NewUserRegistrationRequest(testUsername, "", testPassword1),
			wantError: true,
		},
		{
			name:      "Validate returns error for empty password",
			req:       users.NewUserRegistrationRequest(testUsername, testEmail, ""),
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.req.Validate()
			if (err != nil) != test.wantError {
				assert.Error(t, err)
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
			req:       users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is missing a number",
			req:       users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is too short",
			req:       users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			wantError: true,
		},
		{
			name:      "Validate returns an error when the password is missing a symbol",
			req:       users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
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

func TestUserService_SuccessfulUserAuthentication(t *testing.T) {
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockTokenService := &mTokenService.MockTokenService{}
	mockLoginService := &mLoginService.MockLoginAttemptService{}

	user := createNewUser()
	encryptedPassword, err := crypto.HashString(user.Password)
	assert.NoError(t, err)
	user.Password = encryptedPassword

	mockUserRepo.AddUserFunc = func(u *users.User) error { return nil }
	mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return user }
	mockTokenService.GenerateTokenFunc = func(subject, scope string, expirationTime time.Duration) (string, error) { return "testToken", nil }
	mockLoginService.SaveLoginAttemptFunc = func(attempt *users.UserLoginAttempt) error { return nil }
	mockUserRepo.UpdateUserFunc = func(user *users.User) error { return nil }

	userService := NewUserService(mockUserRepo, mockTokenService, mockLoginService, nil)
	userLoginAttempt := createTestUserLoginRequest()

	_, err = userService.AuthenticateUserWithRequest(userLoginAttempt, testIPAddress, testRequestMetadata, testUserAgent)
	assert.NoError(t, err, "unexpected error during login")
}

func TestUserService_AuthenticateUserInvalidPassword(t *testing.T) {
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockTokenService := &mTokenService.MockTokenService{}
	mockLoginService := &mLoginService.MockLoginAttemptService{}

	user := createNewUser()
	encryptedPassword, err := crypto.HashString(user.Password)
	assert.NoError(t, err)
	user.Password = encryptedPassword

	mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return user }
	mockLoginService.HandleFailedLoginAttemptFunc = func(user *users.User, attempt *users.UserLoginAttempt) error {
		return nil
	}

	userService := NewUserService(mockUserRepo, mockTokenService, mockLoginService, nil)
	userLoginAttempt := createTestUserLoginRequest()
	userLoginAttempt.Password = testInvalidPassword

	_, actual := userService.AuthenticateUserWithRequest(userLoginAttempt, testIPAddress, testRequestMetadata, testUserAgent)

	assert.Error(t, actual, "expected error during authentication")
}

func TestUserService_AuthenticateUser_UserNotFound(t *testing.T) {
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockTokenService := &mTokenService.MockTokenService{}
	mockLoginService := &mLoginService.MockLoginAttemptService{}

	mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return nil }

	loginUser := createNewUser()
	encryptedPassword, err := crypto.HashString(loginUser.Password)
	assert.NoError(t, err)
	loginUser.Password = encryptedPassword

	userService := NewUserService(mockUserRepo, mockTokenService, mockLoginService, nil)
	userLoginAttempt := createTestUserLoginRequest()

	expected := errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
	_, actual := userService.AuthenticateUserWithRequest(userLoginAttempt, testIPAddress, testRequestMetadata, testUserAgent)

	assert.Error(t, actual, "expected error during authentication")
	assert.Equal(t, actual, expected)
}

func TestUserService_ArtificialDelayDuringUserAuthentication(t *testing.T) {
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockTokenService := &mTokenService.MockTokenService{}
	mockLoginService := &mLoginService.MockLoginAttemptService{}

	user := createNewUser()
	encryptedPassword, err := crypto.HashString(user.Password)
	assert.NoError(t, err)
	user.Password = encryptedPassword

	mockUserRepo.AddUserFunc = func(u *users.User) error { return nil }
	mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return user }
	mockUserRepo.UpdateUserFunc = func(user *users.User) error { return nil }
	mockLoginService.HandleFailedLoginAttemptFunc = func(user *users.User, attempt *users.UserLoginAttempt) error {
		return nil
	}

	userService := NewUserService(mockUserRepo, mockTokenService, mockLoginService, nil)
	userLoginAttempt := createTestUserLoginRequest()
	userLoginAttempt.Password = testInvalidPassword

	expected := 500 * time.Millisecond
	startTime := time.Now()
	_, err = userService.AuthenticateUserWithRequest(userLoginAttempt, testIPAddress, testRequestMetadata, testUserAgent)
	actual := time.Since(startTime)

	assert.NotNil(t, err)
	assert.GreaterOrEqual(t, actual, expected, "expected artificial delay of at least 500ms")
}

func TestUserService_AccountLockingDuringUserAuthentication(t *testing.T) {
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockTokenService := &mTokenService.MockTokenService{}
	mockLoginService := &mLoginService.MockLoginAttemptService{}

	user := createNewUser()
	encryptedPassword, err := crypto.HashString(user.Password)
	assert.NoError(t, err)
	user.Password = encryptedPassword
	user.AccountLocked = true

	mockUserRepo.AddUserFunc = func(u *users.User) error { return nil }
	mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return user }
	mockUserRepo.UpdateUserFunc = func(user *users.User) error { return nil }
	mockLoginService.HandleFailedLoginAttemptFunc = func(user *users.User, attempt *users.UserLoginAttempt) error {
		return nil
	}

	userService := NewUserService(mockUserRepo, mockTokenService, mockLoginService, nil)
	userLoginAttempt := createTestUserLoginRequest()
	userLoginAttempt.Password = testInvalidPassword

	maxFailedLoginAttempts := 5
	for range maxFailedLoginAttempts {
		_, err := userService.AuthenticateUserWithRequest(userLoginAttempt, testIPAddress, testRequestMetadata, testUserAgent)
		assert.NotNil(t, err)
	}

	retrievedUser := mockUserRepo.GetUserByIDFunc(testEmail)
	assert.True(t, retrievedUser.AccountLocked, "expected account to be locked")

	_, err = userService.AuthenticateUserWithRequest(userLoginAttempt, testIPAddress, testRequestMetadata, testUserAgent)
	assert.Error(t, err, "expected error on login attempt with locked account")
}

func TestUserService_ValidateVerificationCode(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		userRepo := &mUserRepo.MockUserRepository{
			GetUserByEmailFunc: func(email string) *users.User {
				return createNewUser()
			},
			UpdateUserFunc: func(user *users.User) error {
				return nil
			},
		}
		tokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(token string) error { return nil },
			ParseTokenFunc: func(token string) (*tokens.TokenClaims, error) {
				return &tokens.TokenClaims{
					StandardClaims: &jwt.StandardClaims{
						Subject: testEmail,
					},
				}, nil
			},
		}

		service := NewUserService(userRepo, tokenService, nil, nil)
		err := service.ValidateVerificationCode(testVerificationCode)

		assert.NoError(t, err)
	})

	t.Run("Error is returned when the verification code is not valid", func(t *testing.T) {
		tokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(token string) error {
				return errors.New(errors.ErrCodeUnauthorized, "the verification code is either expired or does not exist")
			},
		}

		service := NewUserService(nil, tokenService, nil, nil)
		err := service.ValidateVerificationCode(testVerificationCode)

		assert.Error(t, err)
		assert.Contains(t, "the verification code is either expired or does not exist", err.Error())
	})

	t.Run("Error is returned when required parameters are missing", func(t *testing.T) {
		service := NewUserService(nil, nil, nil, nil)
		err := service.ValidateVerificationCode("")

		assert.Error(t, err)
		assert.Contains(t, "missing one or more required parameters in the request", err.Error())
	})

	t.Run("Error is returned when parsing the verification code fails", func(t *testing.T) {
		tokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(token string) error { return nil },
			ParseTokenFunc: func(token string) (*tokens.TokenClaims, error) {
				return nil, errors.NewInternalServerError()
			},
		}

		service := NewUserService(nil, tokenService, nil, nil)
		err := service.ValidateVerificationCode(testVerificationCode)

		assert.Error(t, err)
	})

	t.Run("Error is returned when the user does not exist by email", func(t *testing.T) {
		userRepo := &mUserRepo.MockUserRepository{
			GetUserByEmailFunc: func(email string) *users.User { return nil },
		}
		tokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(token string) error { return nil },
			ParseTokenFunc: func(token string) (*tokens.TokenClaims, error) {
				return &tokens.TokenClaims{
					StandardClaims: &jwt.StandardClaims{
						Subject: testEmail,
					},
				}, nil
			},
		}

		service := NewUserService(userRepo, tokenService, nil, nil)
		err := service.ValidateVerificationCode(testVerificationCode)

		assert.Error(t, err)
		assert.Contains(t, "the verification code is invalid", err.Error())
	})
}

func createNewUser() *users.User {
	user := users.NewUser(testUsername, testEmail, testPassword1)
	user.Scopes = []string{clients.UserRead}
	return user
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

func createTestUserLoginRequest() *users.UserLoginRequest {
	return &users.UserLoginRequest{
		ID:       testUserID,
		Username: testUsername,
		Password: testPassword1,
	}
}
