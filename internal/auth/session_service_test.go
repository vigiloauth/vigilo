package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/token"
)

func setupTestEnvironment() (*SessionService, *config.JWTConfig, *token.TokenService, token.TokenBlacklist) {
	jwtConfig := config.NewJWTConfig()
	tokenService := token.NewTokenService(jwtConfig)
	tokenBlacklist := token.GetTokenBlacklist()

	return NewSessionService(tokenService, tokenBlacklist), jwtConfig, tokenService, tokenBlacklist
}

func TestCreateSession(t *testing.T) {
	sessionService, jwtConfig, _, _ := setupTestEnvironment()

	w := httptest.NewRecorder()
	email := "test@example.com"

	err := sessionService.CreateSession(w, email, jwtConfig.ExpirationTime())
	assert.NoError(t, err)

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "session_token", cookie.Name)
	assert.NotEmpty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
}

func TestInvalidateSession(t *testing.T) {
	sessionService, jwtConfig, tokenService, tokenBlacklist := setupTestEnvironment()

	email := "test@example.com"
	validToken, _ := tokenService.GenerateToken(email, jwtConfig.ExpirationTime())

	r := httptest.NewRequest("POST", "/invalidate", nil)
	r.Header.Set("Authorization", "Bearer "+validToken)

	w := httptest.NewRecorder()

	err := sessionService.InvalidateSession(w, r)
	assert.NoError(t, err)

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "session_token", cookie.Name)
	assert.Empty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)

	// Assert the token is blacklisted
	assert.True(t, tokenBlacklist.IsTokenBlacklisted(validToken))
}
