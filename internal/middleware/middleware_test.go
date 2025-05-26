package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
)

const email string = "test@example.com"

func TestAuthMiddleware_ValidToken(t *testing.T) {
	tokenString := "validToken"

	tokenParser := &mocks.MockTokenParser{
		ParseTokenFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
			return &token.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject: email,
				},
			}, nil
		},
	}
	tokenValidator := &mocks.MockTokenValidator{
		ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
			return nil
		},
	}

	middleware := NewMiddleware(tokenParser, tokenValidator)

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
	tokenString := "blacklistedToken"

	tokenParser := &mocks.MockTokenParser{
		ParseTokenFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
			return &token.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject: email,
				},
			}, nil
		},
	}
	tokenValidator := &mocks.MockTokenValidator{
		ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
			return errors.New(errors.ErrCodeUnauthorized, "invalid-token")
		},
	}

	middleware := NewMiddleware(tokenParser, tokenValidator)

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
	tokenParser := &mocks.MockTokenParser{
		ParseTokenFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
			return nil, errors.New(errors.ErrCodeInvalidToken, "invalid-token")
		},
	}

	middleware := NewMiddleware(tokenParser, nil)

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
	middleware := NewMiddleware(nil, nil)

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
	middleware := NewMiddleware(nil, nil)

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
