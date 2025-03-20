package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/mocks"
)

const email string = "test@example.com"

func TestAuthMiddleware_ValidToken(t *testing.T) {
	mockTokenService := &mocks.MockTokenService{}
	mockTokenStore := &mocks.MockTokenStore{}

	tokenString := "validToken"

	mockTokenService.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) {
		return tokenString, nil
	}
	mockTokenService.ParseTokenFunc = func(tokenString string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: email}, nil
	}
	mockTokenStore.IsTokenBlacklistedFunc = func(token string) bool { return false }
	mockTokenService.IsTokenExpiredFunc = func(token string) bool { return false }

	middleware := NewMiddleware(mockTokenService, mockTokenStore)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	handler := middleware.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code, "expected status code to be 200 OK")
}

func TestAuthMiddleware_BlacklistedToken(t *testing.T) {
	mockTokenService := &mocks.MockTokenService{}
	mockTokenStore := &mocks.MockTokenStore{}

	tokenString := "blacklistedToken"

	mockTokenService.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) {
		return tokenString, nil
	}
	mockTokenService.ParseTokenFunc = func(tokenString string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: email}, nil
	}
	mockTokenStore.IsTokenBlacklistedFunc = func(tokenString string) bool {
		return tokenString == "blacklistedToken"
	}

	middleware := NewMiddleware(mockTokenService, mockTokenStore)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	handler := middleware.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	mockTokenService := &mocks.MockTokenService{}
	mockTokenStore := &mocks.MockTokenStore{}

	mockTokenService.ParseTokenFunc = func(tokenString string) (*jwt.StandardClaims, error) { return nil, errors.New("invalid token") }
	mockTokenStore.IsTokenBlacklistedFunc = func(token string) bool { return true }

	middleware := NewMiddleware(mockTokenService, mockTokenStore)

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer invalid.token")
	w := httptest.NewRecorder()

	handler := middleware.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRedirectToHTTPS(t *testing.T) {
	mockTokenService := &mocks.MockTokenService{}
	mockTokenStore := &mocks.MockTokenStore{}
	middleware := NewMiddleware(mockTokenService, mockTokenStore)

	r := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()

	handler := middleware.RedirectToHTTPS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusPermanentRedirect, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("Location"), "https://"))
}

func TestRateLimit(t *testing.T) {
	mockTokenService := &mocks.MockTokenService{}
	mockTokenStore := &mocks.MockTokenStore{}
	middleware := NewMiddleware(mockTokenService, mockTokenStore)

	handler := middleware.RateLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	maxRequestsPerMinute := config.GetServerConfig().MaxRequestsPerMinute()
	for range maxRequestsPerMinute {
		r := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		assert.Equal(t, http.StatusOK, w.Code)
	}

	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}
