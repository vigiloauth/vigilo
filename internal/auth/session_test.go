package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/token"
)

func TestCreateSession(t *testing.T) {
	jwtConfig := config.NewDefaultJWTConfig()

	w := httptest.NewRecorder()
	email := "test@example.com"

	err := CreateSession(w, email, jwtConfig)
	assert.NoError(t, err)

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "session_token", cookie.Name)
	assert.NotEmpty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
}

func TestInvalidateSession(t *testing.T) {
	jwtConfig := config.NewDefaultJWTConfig()

	tokenBlacklist := token.GetTokenBlacklist()

	email := "test@example.com"
	validToken, _ := token.GenerateJWT(email, *jwtConfig)

	r := httptest.NewRequest("POST", "/invalidate", nil)
	r.Header.Set("Authorization", "Bearer "+validToken)

	w := httptest.NewRecorder()

	err := InvalidateSession(w, r, jwtConfig, tokenBlacklist)
	assert.NoError(t, err)

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "session_token", cookie.Name)
	assert.Empty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)

	assert.True(t, tokenBlacklist.IsTokenBlacklisted(validToken))
}
