package service

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/crypto"
	email "github.com/vigiloauth/vigilo/internal/domain/email"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	mEmailService "github.com/vigiloauth/vigilo/internal/mocks/email"
	mTokenService "github.com/vigiloauth/vigilo/internal/mocks/token"
	mUserRepo "github.com/vigiloauth/vigilo/internal/mocks/user"
)

const (
	username       string = "username"
	userEmail      string = "test@email.com"
	userPassword   string = "userPassword"
	baseURL        string = "https://base.com/reset"
	testPassword   string = "pas$_W0Rd"
	testToken      string = "test_token"
	successMessage string = "Password reset instructions have been sent to your email if an account exists."
)

func TestPasswordResetService_SendPasswordResetEmail(t *testing.T) {
	config.NewServerConfig(config.WithBaseURL(baseURL))

	testCases := []struct {
		name              string
		userEmail         string
		mockUserStoreFunc func(email string) *users.User
		mockTokenFunc     func(email string, duration time.Duration) (string, error)
		mockEmailSendFunc func(request email.EmailRequest) error
		expectedError     error
		expectedMessage   string
	}{
		{
			name:      "User not found",
			userEmail: "nonexistent@example.com",
			mockUserStoreFunc: func(email string) *users.User {
				return nil
			},
			expectedMessage: successMessage,
		},
		{
			name:      "Token generation error",
			userEmail: userEmail,
			mockUserStoreFunc: func(email string) *users.User {
				return &users.User{}
			},
			mockTokenFunc: func(email string, duration time.Duration) (string, error) {
				return "", errors.New(errors.ErrCodeTokenCreation, "failed to generate reset token")
			},
			expectedError: errors.New(errors.ErrCodeTokenCreation, "failed to generate reset token: failed to generate reset token"),
		},
		{
			name:      "Email sending error",
			userEmail: userEmail,
			mockUserStoreFunc: func(email string) *users.User {
				return &users.User{}
			},
			mockTokenFunc: func(email string, duration time.Duration) (string, error) {
				return testToken, nil
			},
			mockEmailSendFunc: func(request email.EmailRequest) error {
				return errors.New(errors.ErrCodeEmailDeliveryFailed, "email delivery failed, added to retry queue")
			},
			expectedError: errors.New(errors.ErrCodeEmailDeliveryFailed, "failed to send email: failed to send password reset email"),
		},

		{
			name:      "Success",
			userEmail: userEmail,
			mockUserStoreFunc: func(email string) *users.User {
				return &users.User{}
			},
			mockTokenFunc: func(email string, duration time.Duration) (string, error) {
				return testToken, nil
			},
			mockEmailSendFunc: func(request email.EmailRequest) error {
				return nil
			},
			expectedMessage: successMessage,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockTokenService := &mTokenService.MockTokenService{
				GenerateTokenFunc: tc.mockTokenFunc,
				SaveTokenFunc:     func(token, email string, expiry time.Time) {},
			}

			mockUserRepo := &mUserRepo.MockUserRepository{
				GetUserByIDFunc: tc.mockUserStoreFunc,
			}

			mockEmailService := &mEmailService.MockEmailService{
				GenerateEmailRequestFunc: func(request email.EmailRequest) *email.EmailRequest {
					return &request
				},
				SendEmailFunc: tc.mockEmailSendFunc,
			}

			service := NewPasswordResetService(mockTokenService, mockUserRepo, mockEmailService)
			resp, err := service.SendPasswordResetEmail(tc.userEmail)

			if tc.expectedError != nil {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tc.expectedMessage != "" {
					assert.Equal(t, tc.expectedMessage, resp.Message)
				}

			}
		})
	}
}

func TestPasswordResetService_constructResetURL(t *testing.T) {
	testCases := []struct {
		name          string
		baseURL       string
		expectedURL   string
		expectedError error
	}{
		{
			name:        "Valid URL",
			baseURL:     baseURL,
			expectedURL: fmt.Sprintf("%s?requestId=%s", baseURL, testToken),
		},
		{
			name:          "Empty Base URL",
			baseURL:       "",
			expectedError: errors.New(errors.ErrCodeEmptyInput, "malformed or empty base URL"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config.NewServerConfig(config.WithBaseURL(tc.baseURL))
			service := NewPasswordResetService(nil, nil, nil)
			url, err := service.constructResetURL(testToken)

			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expectedError.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedURL, url)
			}
		})
	}
}

func TestPasswordResetService_ResetPasswordSuccess(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockEmailService := &mEmailService.MockEmailService{}
	existingUser := createTestUser(t)

	mockUserRepo.AddUserFunc = func(user *users.User) error { return nil }
	mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return existingUser }
	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: existingUser.Email}, nil
	}
	mockUserRepo.UpdateUserFunc = func(user *users.User) error { return nil }
	mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

	var capturedToken string
	mockTokenService.DeleteTokenFunc = func(token string) error {
		capturedToken = token
		return nil
	}

	mockTokenService.GetTokenFunc = func(email, token string) (*token.TokenData, error) {
		return nil, nil
	}

	ps := NewPasswordResetService(mockTokenService, mockUserRepo, mockEmailService)
	expected := users.UserPasswordResetResponse{Message: "Password has been reset successfully"}
	actual, err := ps.ResetPassword(existingUser.Email, existingUser.Password, testToken)

	assert.NoError(t, err, "error when updating the password")
	assert.Equal(t, actual.Message, expected.Message)
	assert.Equal(t, testToken, capturedToken, "expected DeleteToken to be called with the correct token")
}

func TestPasswordResetService_ResetPasswordInvalidToken(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockEmailService := &mEmailService.MockEmailService{}
	existingUser := createTestUser(t)

	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
	}

	ps := NewPasswordResetService(mockTokenService, mockUserRepo, mockEmailService)
	_, actual := ps.ResetPassword(existingUser.Email, existingUser.Email, "invalid_token")

	assert.NotNil(t, actual, "expected an error")
	assert.Equal(t, "token_parsing", actual.(*errors.VigiloAuthError).ErrorCode, "expected error code to match")
	assert.Contains(t, actual.Error(), "failed to parse token", "expected error message to contain specific text")
}

func TestPasswordResetService_InvalidJWTClaims(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockEmailService := &mEmailService.MockEmailService{}

	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: "invalidEmail@test.com"}, nil
	}

	ps := NewPasswordResetService(mockTokenService, mockUserRepo, mockEmailService)
	expected := errors.New(errors.ErrCodeUnauthorized, "invalid reset token")
	_, actual := ps.ResetPassword(userEmail, userPassword, testToken)

	assert.NotNil(t, actual)
	assert.Equal(t, actual, expected, "expected errors to match")
}

func TestPasswordResetService_TokenDeletionFailed(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockEmailService := &mEmailService.MockEmailService{}
	existingUser := createTestUser(t)

	mockUserRepo.AddUserFunc = func(user *users.User) error { return nil }
	mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return existingUser }
	mockUserRepo.UpdateUserFunc = func(user *users.User) error { return nil }
	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: userEmail}, nil
	}

	mockTokenService.DeleteTokenFunc = func(token string) error {
		return errors.New(errors.ErrCodeTokenNotFound, "token not found")
	}

	ps := NewPasswordResetService(mockTokenService, mockUserRepo, mockEmailService)
	_, err := ps.ResetPassword(userEmail, userPassword, testToken)
	assert.Error(t, err, "expected an error to be returned")

	vigiloErr, ok := err.(*errors.VigiloAuthError)
	assert.True(t, ok, "expected a VigiloAuthError")

	assert.Equal(t, errors.ErrCodeTokenNotFound, vigiloErr.ErrorCode, "expected correct error code")
	assert.Equal(t, "failed to delete reset token", vigiloErr.ErrorDescription, "expected correct error message")
	assert.Equal(t, "token not found", vigiloErr.Details, "expected correct error details")
	assert.NotNil(t, vigiloErr.WrappedErr, "expected a wrapped error")
}

func TestPasswordResetService_ErrorUpdatingUser(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockEmailService := &mEmailService.MockEmailService{}
	existingUser := createTestUser(t)

	mockUserRepo.AddUserFunc = func(user *users.User) error { return nil }
	mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return existingUser }
	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: userEmail}, nil
	}

	mockUserRepo.UpdateUserFunc = func(user *users.User) error {
		return errors.New(errors.ErrCodeUserNotFound, "user not found")
	}

	ps := NewPasswordResetService(mockTokenService, mockUserRepo, mockEmailService)
	_, err := ps.ResetPassword(userEmail, userPassword, testToken)
	assert.Error(t, err, "expected an error to be returned")

	vigiloErr, ok := err.(*errors.VigiloAuthError)
	assert.True(t, ok, "expected a VigiloAuthError")

	assert.Equal(t, errors.ErrCodeUserNotFound, vigiloErr.ErrorCode, "expected correct error code")
	assert.Contains(t, vigiloErr.Details, "user not found", "expected correct error message")
	assert.Contains(t, vigiloErr.ErrorDescription, "failed to update user", "expected correct error details")
}

func TestPasswordResetService_LockedAccount_UnlockedAfterUpdate(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockEmailService := &mEmailService.MockEmailService{}
	existingUser := createTestUser(t)
	existingUser.AccountLocked = true

	var updatedUser *users.User

	mockUserRepo.AddUserFunc = func(user *users.User) error { return nil }
	mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return existingUser }
	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: userEmail}, nil
	}

	mockUserRepo.UpdateUserFunc = func(user *users.User) error {
		updatedUser = user
		return nil
	}

	mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

	ps := NewPasswordResetService(mockTokenService, mockUserRepo, mockEmailService)
	_, err := ps.ResetPassword(userEmail, userEmail, testToken)

	assert.NoError(t, err, "error occurred when updating user")
	assert.NotNil(t, updatedUser, "updated user should not be nil")
	assert.False(t, updatedUser.AccountLocked, "account should be unlocked after password reset")
}

func createTestUser(t *testing.T) *users.User {
	encryptedPassword, err := crypto.HashString(testPassword)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	return users.NewUser(username, userEmail, encryptedPassword)
}
