package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const invalidToken string = "invalidToken"

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
			tokenService := NewTokenService(GetInMemoryTokenStore())

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
			tokenService := NewTokenService(GetInMemoryTokenStore())

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
	tokenStore := GetInMemoryTokenStore()
	tokenService := NewTokenService(tokenStore)

	tokenService.AddToken(token, email, time.Now().Add(1*time.Hour))

	result, err := tokenService.GetToken(email, token)
	assert.NoError(t, err)
	assert.NotNil(t, result)

	result, err = tokenService.GetToken(email, invalidToken)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestTokenService_IsTokenBlacklisted(t *testing.T) {
	tokenStore := GetInMemoryTokenStore()
	tokenService := NewTokenService(tokenStore)

	tokenStore.AddToken(token, email, time.Now().Add(1*time.Hour))

	isBlacklisted := tokenService.IsTokenBlacklisted(token)
	assert.True(t, isBlacklisted)
}

func TestTokenService_AddToken(t *testing.T) {
	tokenStore := GetInMemoryTokenStore()
	tokenService := NewTokenService(tokenStore)

	tokenStore.AddToken(token, email, time.Now().Add(1*time.Hour))

	tokenData, err := tokenService.GetToken(email, token)
	assert.NoError(t, err)
	assert.NotNil(t, tokenData)
}

func TestTokenService_DeleteToken(t *testing.T) {
	tokenStore := GetInMemoryTokenStore()
	tokenService := NewTokenService(tokenStore)

	tokenStore.AddToken(token, email, time.Now().Add(1*time.Hour))

	err := tokenService.DeleteToken(token)
	assert.NoError(t, err)

	tokenData, err := tokenService.GetToken(email, token)
	assert.Error(t, err)
	assert.Nil(t, tokenData)
}
