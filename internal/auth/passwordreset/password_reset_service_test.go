package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/email"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/mocks"
	"github.com/vigiloauth/vigilo/internal/users"
)

const userEmail string = "test@email.com"
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
			expectedURL: fmt.Sprintf("%s?token=%s", baseURL, testToken),
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
