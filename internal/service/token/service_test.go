package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	token "github.com/vigiloauth/vigilo/internal/repository/token"
)

const (
	testToken        string = "test-token"
	testID           string = "test-id"
	testInvalidToken string = "invalidToken"
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
			tokenService := NewTokenServiceImpl(token.GetInMemoryTokenRepository())

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
			tokenService := NewTokenServiceImpl(token.GetInMemoryTokenRepository())

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
	tokenService := NewTokenServiceImpl(token.GetInMemoryTokenRepository())
	tokenService.SaveToken(testToken, testID, time.Now().Add(1*time.Hour))

	result, err := tokenService.GetToken(testID, testToken)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	result, err = tokenService.GetToken(testID, testInvalidToken)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestTokenService_IsTokenBlacklisted(t *testing.T) {
	tokenStore := token.GetInMemoryTokenRepository()
	tokenService := NewTokenServiceImpl(tokenStore)

	tokenStore.SaveToken(testToken, testID, time.Now().Add(1*time.Hour))

	isBlacklisted := tokenService.IsTokenBlacklisted(testToken)
	assert.True(t, isBlacklisted)
}

func TestTokenService_AddToken(t *testing.T) {
	token := token.GetInMemoryTokenRepository()
	tokenService := NewTokenServiceImpl(token)

	token.SaveToken(testToken, testID, time.Now().Add(1*time.Hour))

	tokenData, err := tokenService.GetToken(testID, testToken)
	assert.NoError(t, err)
	assert.NotNil(t, tokenData)
}

func TestTokenService_DeleteToken(t *testing.T) {
	tokenRepo := token.GetInMemoryTokenRepository()
	tokenService := NewTokenServiceImpl(tokenRepo)

	tokenRepo.SaveToken(testToken, testID, time.Now().Add(1*time.Hour))

	err := tokenService.DeleteToken(testToken)
	assert.NoError(t, err)

	tokenData, err := tokenService.GetToken(testID, testToken)
	assert.Error(t, err)
	assert.Nil(t, tokenData)
}

func TestTokenService_GenerateTokens(t *testing.T) {}
