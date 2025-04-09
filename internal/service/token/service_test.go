package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	domain "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	mTokenRepo "github.com/vigiloauth/vigilo/internal/mocks/token"
)

const (
	testToken        string = "test-token"
	testID           string = "test-id"
	testInvalidToken string = "invalidToken"
	testClientID     string = "client-id"
)

func TestTokenService_GenerateToken(t *testing.T) {
	tests := []struct {
		name           string
		subject        string
		expirationTime time.Duration
		expectError    bool
	}{
		{
			name:           "Valid token generation",
			subject:        "user123",
			expirationTime: time.Hour,
			expectError:    false,
		},
		{
			name:           "Zero expiration time",
			subject:        "user123",
			expirationTime: 0,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTokenRepo := &mTokenRepo.MockTokenRepository{
				SaveTokenFunc:       func(token, id string, expiration time.Time) {},
				ExistsByTokenIDFunc: func(tokenID string) bool { return false },
			}
			tokenService := NewTokenServiceImpl(mockTokenRepo)

			tokenString, err := tokenService.GenerateToken(tt.subject, tt.expirationTime)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, tokenString)
			}
		})
	}
}

func TestTokenService_ParseToken(t *testing.T) {
	tests := []struct {
		name            string
		tokenString     string
		expectError     bool
		expectedSubject string
	}{
		{
			name:            "Valid token",
			tokenString:     "valid_token_string",
			expectError:     false,
			expectedSubject: "user123",
		},
		{
			name:            "Invalid token",
			tokenString:     "invalid_token_string",
			expectError:     true,
			expectedSubject: "",
		},
		{
			name:            "Expired token",
			tokenString:     "expired_token_string",
			expectError:     true,
			expectedSubject: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockTokenRepo := &mTokenRepo.MockTokenRepository{
				SaveTokenFunc:       func(token, id string, expiration time.Time) {},
				ExistsByTokenIDFunc: func(tokenID string) bool { return false },
			}
			tokenService := NewTokenServiceImpl(mockTokenRepo)

			if tt.tokenString == "valid_token_string" {
				validToken, err := tokenService.GenerateToken(tt.expectedSubject, time.Hour)
				require.NoError(t, err)
				tt.tokenString = validToken
			}

			claims, err := tokenService.ParseToken(tt.tokenString)
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSubject, claims.Subject)
			}
		})
	}
}

func TestTokenService_GetToken(t *testing.T) {
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		GetTokenFunc: func(token, id string) (*domain.TokenData, error) {
			return &domain.TokenData{
				Token: testToken,
				ID:    testID,
			}, nil
		},
	}

	tokenService := NewTokenServiceImpl(mockTokenRepo)

	result, err := tokenService.GetToken(testID, testToken)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTokenService_IsTokenBlacklisted(t *testing.T) {
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		IsTokenBlacklistedFunc: func(token string) bool { return true },
	}

	tokenService := NewTokenServiceImpl(mockTokenRepo)

	isBlacklisted := tokenService.IsTokenBlacklisted(testToken)
	assert.True(t, isBlacklisted)
}

func TestTokenService_DeleteToken(t *testing.T) {
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		DeleteTokenFunc: func(token string) error { return nil },
	}

	tokenService := NewTokenServiceImpl(mockTokenRepo)

	err := tokenService.DeleteToken(testToken)
	assert.NoError(t, err)
}

func TestTokenService_GenerateTokenPair(t *testing.T) {
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		SaveTokenFunc:       func(token, id string, expiration time.Time) {},
		ExistsByTokenIDFunc: func(tokenID string) bool { return false },
	}

	tokenService := NewTokenServiceImpl(mockTokenRepo)
	accessToken, refreshToken, err := tokenService.GenerateTokenPair(testID, testClientID)

	assert.NoError(t, err)
	assert.NotEqual(t, "", accessToken)
	assert.NotEqual(t, "", refreshToken)
}

func TestTokenService_DeleteTokenAsync(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockTokenRepo := &mTokenRepo.MockTokenRepository{
			DeleteTokenFunc: func(token string) error {
				return nil
			},
		}

		service := NewTokenServiceImpl(mockTokenRepo)
		errChan := service.DeleteTokenAsync("test-token")

		select {
		case err := <-errChan:
			assert.NoError(t, err, "Expected no error for successful token deletion")
		case <-time.After(1 * time.Second):
			t.Fatal("Test timed out waiting for DeleteTokenAsync to finish")
		}
	})

	t.Run("Retry and Fail", func(t *testing.T) {
		mockTokenRepo := &mTokenRepo.MockTokenRepository{
			DeleteTokenFunc: func(token string) error {
				return errors.New(errors.ErrCodeInternalServerError, "failed to delete token")
			},
		}

		service := NewTokenServiceImpl(mockTokenRepo)
		errChan := service.DeleteTokenAsync("test-token")

		select {
		case err := <-errChan:
			assert.Error(t, err, "Expected an error after all retries fail")
			assert.Equal(t, "failed to delete token", err.Error(), "Expected the correct error message")
		case <-time.After(4 * time.Second):
			t.Fatal("Test timed out waiting for DeleteTokenAsync to finish")
		}
	})

	t.Run("Retry and Succeed", func(t *testing.T) {
		attempts := 0
		mockTokenRepo := &mTokenRepo.MockTokenRepository{
			DeleteTokenFunc: func(token string) error {
				attempts++
				if attempts <= 2 {
					return errors.New(errors.ErrCodeInternalServerError, "failed to delete token")
				}
				return nil
			},
		}

		service := NewTokenServiceImpl(mockTokenRepo)
		errChan := service.DeleteTokenAsync("test-token")

		select {
		case err := <-errChan:
			assert.NoError(t, err, "Expected no error after successful retry")
			assert.Equal(t, 3, attempts, "Expected 3 attempts before success")
		case <-time.After(2 * time.Second):
			t.Fatal("Test timed out waiting for DeleteTokenAsync to finish")
		}
	})
}
