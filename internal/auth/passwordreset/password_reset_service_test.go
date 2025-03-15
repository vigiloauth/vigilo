package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/email"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/mocks"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

const userEmail string = "test@email.com"
const userPassword string = "userPassword"
const baseURL string = "https://base.com/reset"
const testToken string = "test_token"
const successMessage string = "Password reset instructions have been sent to your email if an account exists."

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
				return "", errors.NewTokenGenerationError()
			},
			expectedError: fmt.Errorf("Failed to generate reset token: %w", errors.NewTokenGenerationError()),
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
				return errors.NewBaseError(errors.ErrCodeEmailDeliveryFailed, "Email delivery failed, added to retry queue")
			},
			expectedError: fmt.Errorf("Failed to send email: %w", errors.NewBaseError(errors.ErrCodeEmailDeliveryFailed, "Email delivery failed, added to retry queue")),
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
			mockTokenManager := &mocks.MockTokenManager{
				GenerateTokenFunc: tc.mockTokenFunc,
				AddTokenFunc:      func(token, email string, expiry time.Time) {},
			}

			mockUserStore := &mocks.MockUserStore{
				GetUserFunc: tc.mockUserStoreFunc,
			}

			mockEmailService := &mocks.MockEmailService{
				GenerateEmailFunc: func(request email.EmailRequest) *email.EmailRequest {
					return &request
				},
				SendEmailFunc: tc.mockEmailSendFunc,
			}

			service := NewPasswordResetService(mockTokenManager, mockUserStore, mockEmailService)
			resp, err := service.SendPasswordResetEmail(tc.userEmail)

			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.EqualError(t, err, tc.expectedError.Error())
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
			expectedError: errors.NewEmptyInputError("Base URL"),
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
	mockTokenService := &mocks.MockTokenManager{}
	mockUserStore := &mocks.MockUserStore{}
	mockEmailService := &mocks.MockEmailService{}
	existingUser := createTestUser(t)

	mockUserStore.AddUserFunc = func(user *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(value string) *users.User { return existingUser }
	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: existingUser.Email}, nil
	}
	mockUserStore.UpdateUserFunc = func(user *users.User) error { return nil }
	mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

	var capturedToken string
	mockTokenService.DeleteTokenFunc = func(token string) error {
		capturedToken = token
		return nil
	}
	mockTokenService.GetTokenFunc = func(email, token string) (*token.TokenData, error) {
		return nil, nil
	}

	ps := NewPasswordResetService(mockTokenService, mockUserStore, mockEmailService)
	expected := users.UserPasswordResetResponse{Message: "Password has been reset successfully"}
	actual, err := ps.ResetPassword(existingUser.Email, existingUser.Password, testToken)

	assert.NoError(t, err, "error when updating the password")
	assert.Equal(t, actual.Message, expected.Message)
	assert.Equal(t, testToken, capturedToken, "expected DeleteToken to be called with the correct token")
}

func TestPasswordResetService_ResetPasswordInvalidToken(t *testing.T) {
	mockTokenService := &mocks.MockTokenManager{}
	mockUserStore := &mocks.MockUserStore{}
	mockEmailService := &mocks.MockEmailService{}
	existingUser := createTestUser(t)

	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return nil, errors.NewInvalidTokenError()
	}

	ps := NewPasswordResetService(mockTokenService, mockUserStore, mockEmailService)
	expected := errors.NewInvalidTokenError()
	_, actual := ps.ResetPassword(existingUser.Email, existingUser.Email, "invalid_token")

	assert.Equal(t, actual, expected, "expected errors to match")
}

func TestPasswordResetService_InvalidJWTClaims(t *testing.T) {
	mockTokenService := &mocks.MockTokenManager{}
	mockUserStore := &mocks.MockUserStore{}
	mockEmailService := &mocks.MockEmailService{}

	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: "invalidEmail@test.com"}, nil
	}

	ps := NewPasswordResetService(mockTokenService, mockUserStore, mockEmailService)
	expected := errors.NewUnauthorizedError("Invalid token")
	_, actual := ps.ResetPassword(userEmail, userPassword, testToken)

	assert.NotNil(t, actual)
	assert.Equal(t, actual, expected, "expected errors to match")
}

func TestPasswordResetService_TokenDeletionFailed(t *testing.T) {
	mockTokenService := &mocks.MockTokenManager{}
	mockUserStore := &mocks.MockUserStore{}
	mockEmailService := &mocks.MockEmailService{}
	existingUser := createTestUser(t)

	mockUserStore.AddUserFunc = func(user *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(value string) *users.User { return existingUser }
	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: userEmail}, nil
	}
	mockUserStore.UpdateUserFunc = func(user *users.User) error { return nil }
	mockTokenService.DeleteTokenFunc = func(token string) error {
		return errors.NewTokenNotFoundError()
	}

	ps := NewPasswordResetService(mockTokenService, mockUserStore, mockEmailService)

	expected := errors.Wrap(errors.NewTokenNotFoundError(), "Failed to delete reset token")
	_, actual := ps.ResetPassword(userEmail, userPassword, testToken)

	assert.NotNil(t, actual)
	assert.Equal(t, actual.Error(), expected.Error())
}

func TestPasswordResetService_ErrorUpdatingUser(t *testing.T) {
	mockTokenService := &mocks.MockTokenManager{}
	mockUserStore := &mocks.MockUserStore{}
	mockEmailService := &mocks.MockEmailService{}
	existingUser := createTestUser(t)

	mockUserStore.AddUserFunc = func(user *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(value string) *users.User { return existingUser }
	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: userEmail}, nil
	}
	mockUserStore.UpdateUserFunc = func(user *users.User) error {
		return errors.NewUserNotFoundError()
	}

	ps := NewPasswordResetService(mockTokenService, mockUserStore, mockEmailService)

	expected := errors.Wrap(errors.NewUserNotFoundError(), "Failed to update user")
	_, actual := ps.ResetPassword(userEmail, userPassword, testToken)

	assert.NotNil(t, actual)
	assert.Equal(t, actual.Error(), expected.Error())
}

func TestPasswordResetService_LockedAccount_UnlockedAfterUpdate(t *testing.T) {
	mockTokenService := &mocks.MockTokenManager{}
	mockUserStore := &mocks.MockUserStore{}
	mockEmailService := &mocks.MockEmailService{}
	existingUser := createTestUser(t)
	existingUser.AccountLocked = true

	var updatedUser *users.User

	mockUserStore.AddUserFunc = func(user *users.User) error { return nil }
	mockUserStore.GetUserFunc = func(value string) *users.User { return existingUser }
	mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: userEmail}, nil
	}
	mockUserStore.UpdateUserFunc = func(user *users.User) error {
		updatedUser = user
		return nil
	}
	mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

	ps := NewPasswordResetService(mockTokenService, mockUserStore, mockEmailService)

	_, err := ps.ResetPassword(userEmail, userEmail, testToken)
	assert.NoError(t, err, "error occurred when updating user")

	assert.NotNil(t, updatedUser, "updated user should not be nil")
	assert.False(t, updatedUser.AccountLocked, "account should be unlocked after password reset")
}

func createTestUser(t *testing.T) *users.User {
	encryptedPassword, err := utils.HashPassword(utils.TestPassword1)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	return users.NewUser(utils.TestUsername, utils.TestEmail, encryptedPassword)
}
