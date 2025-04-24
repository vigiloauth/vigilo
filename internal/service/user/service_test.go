package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/internal/crypto"
	domain "github.com/vigiloauth/vigilo/internal/domain/audit"
	email "github.com/vigiloauth/vigilo/internal/domain/email"
	tokens "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	mAuditLogger "github.com/vigiloauth/vigilo/internal/mocks/audit"
	mEmailService "github.com/vigiloauth/vigilo/internal/mocks/email"
	mLoginService "github.com/vigiloauth/vigilo/internal/mocks/login"
	mTokenService "github.com/vigiloauth/vigilo/internal/mocks/token"
	mUserRepo "github.com/vigiloauth/vigilo/internal/mocks/user"
	"github.com/vigiloauth/vigilo/internal/utils"
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
	ctx := context.Background()
	mockUserRepo := &mUserRepo.MockUserRepository{
		GetUserByEmailFunc: func(ctx context.Context, email string) (*users.User, error) {
			return nil, nil
		},
		AddUserFunc: func(ctx context.Context, user *users.User) error {
			return nil
		},
	}
	mockTokenService := &mTokenService.MockTokenService{
		GenerateTokenFunc: func(ctx context.Context, id, scopes, roles string, duration time.Duration) (string, error) {
			return testToken, nil
		},
	}
	mockEmailService := &mEmailService.MockEmailService{
		SendEmailFunc: func(ctx context.Context, request *email.EmailRequest) error {
			return nil
		},
	}
	mockAuditLogger := &mAuditLogger.MockAuditLogger{
		StoreEventFunc: func(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
		},
	}

	userService := NewUserService(mockUserRepo, mockTokenService, nil, mockEmailService, mockAuditLogger)
	registeredUser, err := userService.CreateUser(ctx, createNewUser())

	assert.NoError(t, err)
	assert.NotNil(t, registeredUser)
}

func TestUserService_CreateUser_DuplicateEntry(t *testing.T) {
	ctx := context.Background()
	mockUserRepo := &mUserRepo.MockUserRepository{
		AddUserFunc: func(ctx context.Context, user *users.User) error {
			return errors.NewInternalServerError()
		},
		GetUserByEmailFunc: func(ctx context.Context, email string) (*users.User, error) {
			return nil, nil
		},
	}
	mockAuditLogger := &mAuditLogger.MockAuditLogger{
		StoreEventFunc: func(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
		},
	}

	user := createNewUser()
	userService := NewUserService(mockUserRepo, nil, nil, nil, mockAuditLogger)
	_, err := userService.CreateUser(ctx, user)

	assert.Error(t, err)
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
	ctx := context.Background()
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyIPAddress, testIPAddress)
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserAgent, testUserAgent)

	user := createNewUser()
	encryptedPassword, err := crypto.HashString(user.Password)
	assert.NoError(t, err)
	user.Password = encryptedPassword

	mockUserRepo := &mUserRepo.MockUserRepository{
		GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
			return user, nil
		},
		UpdateUserFunc: func(ctx context.Context, user *users.User) error {
			return nil
		},
	}
	mockTokenService := &mTokenService.MockTokenService{
		GenerateTokenFunc: func(ctx context.Context, id, scopes, roles string, duration time.Duration) (string, error) {
			return "testToken", nil
		},
	}
	mockLoginService := &mLoginService.MockLoginAttemptService{
		SaveLoginAttemptFunc: func(ctx context.Context, attempt *users.UserLoginAttempt) error {
			return nil
		},
	}
	mockAuditLogger := &mAuditLogger.MockAuditLogger{
		StoreEventFunc: func(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
		},
	}

	userService := NewUserService(mockUserRepo, mockTokenService, mockLoginService, nil, mockAuditLogger)
	userLoginAttempt := createTestUserLoginRequest()

	_, err = userService.AuthenticateUserWithRequest(ctx, userLoginAttempt)
	assert.NoError(t, err, "unexpected error during login")
}

func TestUserService_AuthenticateUserInvalidPassword(t *testing.T) {
	ctx := context.Background()
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyIPAddress, testIPAddress)
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserAgent, testUserAgent)

	mockUserRepo := &mUserRepo.MockUserRepository{
		GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
			return nil, nil
		},
	}
	mockLoginService := &mLoginService.MockLoginAttemptService{
		HandleFailedLoginAttemptFunc: func(ctx context.Context, user *users.User, attempt *users.UserLoginAttempt) error {
			return nil
		},
	}
	mockAuditLogger := &mAuditLogger.MockAuditLogger{
		StoreEventFunc: func(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
		},
	}

	userService := NewUserService(mockUserRepo, nil, mockLoginService, nil, mockAuditLogger)
	userLoginAttempt := createTestUserLoginRequest()
	userLoginAttempt.Password = testInvalidPassword

	_, actual := userService.AuthenticateUserWithRequest(ctx, userLoginAttempt)

	assert.Error(t, actual, "expected error during authentication")
}

func TestUserService_AuthenticateUser_UserNotFound(t *testing.T) {
	ctx := context.Background()
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyIPAddress, testIPAddress)
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserAgent, testUserAgent)

	mockUserRepo := &mUserRepo.MockUserRepository{
		GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
			return nil, nil
		},
	}

	mockAuditLogger := &mAuditLogger.MockAuditLogger{
		StoreEventFunc: func(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
		},
	}

	loginUser := createNewUser()
	encryptedPassword, err := crypto.HashString(loginUser.Password)
	assert.NoError(t, err)
	loginUser.Password = encryptedPassword

	userService := NewUserService(mockUserRepo, nil, nil, nil, mockAuditLogger)
	userLoginAttempt := createTestUserLoginRequest()

	expected := errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
	_, actual := userService.AuthenticateUserWithRequest(ctx, userLoginAttempt)

	assert.Error(t, actual, "expected error during authentication")
	assert.Equal(t, actual, expected)
}

func TestUserService_ArtificialDelayDuringUserAuthentication(t *testing.T) {
	ctx := context.Background()
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyIPAddress, testIPAddress)
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserAgent, testUserAgent)

	user := createNewUser()
	encryptedPassword, err := crypto.HashString(user.Password)
	assert.NoError(t, err)
	user.Password = encryptedPassword

	mockUserRepo := &mUserRepo.MockUserRepository{
		GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
			return user, nil
		},
		UpdateUserFunc: func(ctx context.Context, user *users.User) error {
			return nil
		},
	}
	mockLoginService := &mLoginService.MockLoginAttemptService{
		HandleFailedLoginAttemptFunc: func(ctx context.Context, user *users.User, attempt *users.UserLoginAttempt) error {
			return nil
		},
	}
	mockAuditLogger := &mAuditLogger.MockAuditLogger{
		StoreEventFunc: func(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
		},
	}

	userService := NewUserService(mockUserRepo, nil, mockLoginService, nil, mockAuditLogger)
	userLoginAttempt := createTestUserLoginRequest()
	userLoginAttempt.Password = testInvalidPassword

	expected := 500 * time.Millisecond
	startTime := time.Now()
	_, err = userService.AuthenticateUserWithRequest(ctx, userLoginAttempt)
	actual := time.Since(startTime)

	assert.NotNil(t, err)
	assert.GreaterOrEqual(t, actual, expected, "expected artificial delay of at least 500ms")
}

func TestUserService_AccountLockingDuringUserAuthentication(t *testing.T) {
	ctx := context.Background()
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyIPAddress, testIPAddress)
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserAgent, testUserAgent)

	user := createNewUser()
	encryptedPassword, err := crypto.HashString(user.Password)
	assert.NoError(t, err)
	user.Password = encryptedPassword
	user.AccountLocked = true

	mockUserRepo := &mUserRepo.MockUserRepository{
		GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
			return user, nil
		},
		UpdateUserFunc: func(ctx context.Context, user *users.User) error {
			return nil
		},
	}
	mockLoginService := &mLoginService.MockLoginAttemptService{
		HandleFailedLoginAttemptFunc: func(ctx context.Context, user *users.User, attempt *users.UserLoginAttempt) error {
			return nil
		},
	}
	mockAuditLogger := &mAuditLogger.MockAuditLogger{
		StoreEventFunc: func(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
		},
	}

	userService := NewUserService(mockUserRepo, nil, mockLoginService, nil, mockAuditLogger)
	userLoginAttempt := createTestUserLoginRequest()
	userLoginAttempt.Password = testInvalidPassword

	maxFailedLoginAttempts := 5
	for range maxFailedLoginAttempts {
		_, err := userService.AuthenticateUserWithRequest(ctx, userLoginAttempt)
		assert.NotNil(t, err)
	}

	retrievedUser, err := mockUserRepo.GetUserByIDFunc(ctx, testEmail)
	assert.NoError(t, err)
	assert.True(t, retrievedUser.AccountLocked, "expected account to be locked")

	_, err = userService.AuthenticateUserWithRequest(ctx, userLoginAttempt)
	assert.Error(t, err, "expected error on login attempt with locked account")
}

func TestUserService_ValidateVerificationCode(t *testing.T) {
	ctx := context.Background()
	t.Run("Success", func(t *testing.T) {
		userRepo := &mUserRepo.MockUserRepository{
			GetUserByEmailFunc: func(ctx context.Context, email string) (*users.User, error) {
				return createNewUser(), nil
			},
			UpdateUserFunc: func(ctx context.Context, user *users.User) error {
				return nil
			},
		}
		tokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(ctx context.Context, token string) error { return nil },
			ParseTokenFunc: func(token string) (*tokens.TokenClaims, error) {
				return &tokens.TokenClaims{
					StandardClaims: &jwt.StandardClaims{
						Subject: testEmail,
					},
				}, nil
			},
		}

		service := NewUserService(userRepo, tokenService, nil, nil, nil)
		err := service.ValidateVerificationCode(ctx, testVerificationCode)

		assert.NoError(t, err)
	})

	t.Run("Error is returned when the verification code is not valid", func(t *testing.T) {
		tokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(ctx context.Context, token string) error {
				return errors.New(errors.ErrCodeUnauthorized, "the verification code is either expired or does not exist")
			},
		}

		service := NewUserService(nil, tokenService, nil, nil, nil)
		err := service.ValidateVerificationCode(ctx, testVerificationCode)

		assert.Error(t, err)
		assert.Contains(t, "the verification code is either expired or does not exist", err.Error())
	})

	t.Run("Error is returned when required parameters are missing", func(t *testing.T) {
		service := NewUserService(nil, nil, nil, nil, nil)
		err := service.ValidateVerificationCode(ctx, "")

		assert.Error(t, err)
		assert.Contains(t, "missing one or more required parameters in the request", err.Error())
	})

	t.Run("Error is returned when parsing the verification code fails", func(t *testing.T) {
		tokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(ctx context.Context, token string) error { return nil },
			ParseTokenFunc: func(token string) (*tokens.TokenClaims, error) {
				return nil, errors.NewInternalServerError()
			},
		}

		service := NewUserService(nil, tokenService, nil, nil, nil)
		err := service.ValidateVerificationCode(ctx, testVerificationCode)

		assert.Error(t, err)
	})

	t.Run("Error is returned when the user does not exist by email", func(t *testing.T) {
		userRepo := &mUserRepo.MockUserRepository{
			GetUserByEmailFunc: func(ctx context.Context, email string) (*users.User, error) { return nil, nil },
		}
		tokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(ctx context.Context, token string) error { return nil },
			ParseTokenFunc: func(token string) (*tokens.TokenClaims, error) {
				return &tokens.TokenClaims{
					StandardClaims: &jwt.StandardClaims{
						Subject: testEmail,
					},
				}, nil
			},
		}

		service := NewUserService(userRepo, tokenService, nil, nil, nil)
		err := service.ValidateVerificationCode(ctx, testVerificationCode)

		assert.Error(t, err)
		assert.Contains(t, "the verification code is invalid", err.Error())
	})
}

func createNewUser() *users.User {
	user := users.NewUser(testUsername, testEmail, testPassword1)
	user.Scopes = []string{constants.UserRead}
	user.Roles = []string{constants.AdminRole}
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
