package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mTokenRepo "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
)

const (
	testToken        string = "test-token"
	testID           string = "test-id"
	testInvalidToken string = "invalidToken"
	testScopes       string = "clients:read"
	testClientID     string = "client-id"
	testRoles        string = "ADMIN"
)

func TestTokenService_GenerateToken(t *testing.T) {
	ctx := context.Background()
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
				SaveTokenFunc: func(ctx context.Context, token, id string, expiration time.Time) error {
					return nil
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
			}

			tokenService := NewTokenService(mockTokenRepo)
			tokenString, err := tokenService.GenerateToken(ctx, tt.subject, testScopes, testRoles, tt.expirationTime)

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
	ctx := context.Background()
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
				SaveTokenFunc: func(ctx context.Context, token, id string, expiration time.Time) error {
					return nil
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
			}

			tokenService := NewTokenService(mockTokenRepo)
			if tt.tokenString == "valid_token_string" {
				validToken, err := tokenService.GenerateToken(ctx, tt.expectedSubject, testScopes, testRoles, time.Hour)
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
	ctx := context.Background()
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		GetTokenFunc: func(ctx context.Context, token string) (*domain.TokenData, error) {
			return &domain.TokenData{
				Token: testToken,
				ID:    testID,
			}, nil
		},
	}

	tokenService := NewTokenService(mockTokenRepo)

	result, err := tokenService.GetToken(ctx, testToken)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTokenService_IsTokenBlacklisted(t *testing.T) {
	ctx := context.Background()
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
			return true, nil
		},
	}

	tokenService := NewTokenService(mockTokenRepo)

	isBlacklisted, err := tokenService.IsTokenBlacklisted(ctx, testToken)
	assert.NoError(t, err)
	assert.True(t, isBlacklisted)
}

func TestTokenService_DeleteToken(t *testing.T) {
	ctx := context.Background()
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		DeleteTokenFunc: func(ctx context.Context, token string) error {
			return nil
		},
	}

	tokenService := NewTokenService(mockTokenRepo)

	err := tokenService.DeleteToken(ctx, testToken)
	assert.NoError(t, err)
}

func TestTokenService_GenerateTokenPair(t *testing.T) {
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		SaveTokenFunc: func(ctx context.Context, token, id string, expiration time.Time) error {
			return nil
		},
		ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
			return false, nil
		},
	}

	tokenService := NewTokenService(mockTokenRepo)
	ctx := context.Background()

	accessToken, refreshToken, err := tokenService.GenerateTokensWithAudience(ctx, testID, testScopes, testRoles, testClientID)
	assert.NoError(t, err)
	assert.NotEqual(t, "", accessToken)
	assert.NotEqual(t, "", refreshToken)
}

func TestTokenService_DeleteTokenAsync(t *testing.T) {
	ctx := context.Background()
	t.Run("Success", func(t *testing.T) {
		mockTokenRepo := &mTokenRepo.MockTokenRepository{
			DeleteTokenFunc: func(ctx context.Context, token string) error {
				return nil
			},
		}

		service := NewTokenService(mockTokenRepo)
		errChan := service.DeleteTokenAsync(ctx, "test-token")

		select {
		case err := <-errChan:
			assert.NoError(t, err, "Expected no error for successful token deletion")
		case <-time.After(1 * time.Second):
			t.Fatal("Test timed out waiting for DeleteTokenAsync to finish")
		}
	})

	t.Run("Retry and Fail", func(t *testing.T) {
		mockTokenRepo := &mTokenRepo.MockTokenRepository{
			DeleteTokenFunc: func(ctx context.Context, token string) error {
				return errors.New(errors.ErrCodeInternalServerError, "failed to delete token")
			},
		}

		service := NewTokenService(mockTokenRepo)
		errChan := service.DeleteTokenAsync(ctx, "test-token")

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
			DeleteTokenFunc: func(ctx context.Context, token string) error {
				attempts++
				if attempts <= 2 {
					return errors.New(errors.ErrCodeInternalServerError, "failed to delete token")
				}
				return nil
			},
		}

		service := NewTokenService(mockTokenRepo)
		errChan := service.DeleteTokenAsync(ctx, "test-token")

		select {
		case err := <-errChan:
			assert.NoError(t, err, "Expected no error after successful retry")
			assert.Equal(t, 3, attempts, "Expected 3 attempts before success")
		case <-time.After(2 * time.Second):
			t.Fatal("Test timed out waiting for DeleteTokenAsync to finish")
		}
	})
}
