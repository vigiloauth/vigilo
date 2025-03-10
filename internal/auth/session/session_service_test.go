package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/mocks"
)

const testEmail string = "test@example.com"
const testToken string = "test_token"

func TestCreateSession(t *testing.T) {
	mockTokenManager := &mocks.MockTokenManager{}
	mockTokenStore := &mocks.MockTokenStore{}

	mockTokenManager.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) {
		return testToken, nil
	}

	sessionService := NewSessionService(mockTokenManager, mockTokenStore)

	w := httptest.NewRecorder()
	jwtConfig := config.NewJWTConfig()
	err := sessionService.CreateSession(w, testEmail, jwtConfig.ExpirationTime())
	assert.NoError(t, err)

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "session_token", cookie.Name)
	assert.NotEmpty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
}

func TestInvalidateSession(t *testing.T) {
	mockTokenManager := &mocks.MockTokenManager{}
	mockTokenStore := &mocks.MockTokenStore{}
	config.NewJWTConfig()

	mockTokenManager.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) {
		return testToken, nil
	}

	mockTokenManager.ParseTokenFunc = func(tokenString string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: testEmail}, nil
	}

	mockTokenStore.IsTokenBlacklistedFunc = func(tokenString string) bool { return false }
	mockTokenStore.AddTokenFunc = func(tokenString, email string, expirationTime time.Time) {}
	mockTokenStore.IsTokenBlacklistedFunc = func(tokenString string) bool { return tokenString == testToken }

	sessionService := NewSessionService(mockTokenManager, mockTokenStore)

	r := httptest.NewRequest("POST", "/invalidate", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)

	w := httptest.NewRecorder()

	err := sessionService.InvalidateSession(w, r)
	assert.NoError(t, err)

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "session_token", cookie.Name)
	assert.Empty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)

	assert.True(t, mockTokenStore.IsTokenBlacklistedFunc(testToken), "token should be blacklisted")
}
