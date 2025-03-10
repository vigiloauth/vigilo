package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/token"
)

const email string = "test@example.com"

func setupMiddlewareTests() *token.TokenService {
	config.NewServerConfig()
	return token.NewTokenService(token.GetInMemoryTokenStore())
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	tokenService := setupMiddlewareTests()
	middleware := NewMiddleware(tokenService)
	tokenString, _ := tokenService.GenerateToken(email, config.GetServerConfig().JWTConfig().ExpirationTime())

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
	tokenService := setupMiddlewareTests()
	middleware := NewMiddleware(tokenService)

	tokenString, _ := tokenService.GenerateToken(email, config.GetServerConfig().JWTConfig().ExpirationTime())
	token.GetInMemoryTokenStore().AddToken(tokenString, email, time.Now().Add(1*time.Hour))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	handler := middleware.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code, "expected status code to be 401 Unauthorized")
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	tokenService := setupMiddlewareTests()
	middleware := NewMiddleware(tokenService)

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
	middleware := NewMiddleware(nil)

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
	middleware := NewMiddleware(nil)

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
