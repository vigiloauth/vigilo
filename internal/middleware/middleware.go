package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/utils"
)

const maxRequestsForStrictRateLimiting int = 3

// Middleware encapsulates middleware functionalities.
type Middleware struct {
	serverConfig *config.ServerConfig // Server configuration.
	tokenManager token.TokenService   // Token manager for JWT operations.
	tokenStore   token.TokenStore     // Token store for blacklisted tokens.
	rateLimiter  *RateLimiter         // Rate limiter for request rate limiting.
}

// NewMiddleware creates a new Middleware instance.
//
// Parameters:
//
//	tokenManager token.TokenManager: The token manager.
//	tokenStore token.TokenStore: The token store.
//
// Returns:
//
//	*Middleware: A new Middleware instance.
func NewMiddleware(tokenManager token.TokenService, tokenStore token.TokenStore) *Middleware {
	serverConfig := config.GetServerConfig()
	return &Middleware{
		serverConfig: serverConfig,
		tokenStore:   tokenStore,
		tokenManager: tokenManager,
		rateLimiter:  NewRateLimiter(serverConfig.MaxRequestsPerMinute()),
	}
}

// AuthMiddleware is a middleware that checks for a valid JWT token in the Authorization header.
func (m *Middleware) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				err := errors.New(errors.ErrCodeMissingHeader, "authorization header is missing")
				utils.WriteError(w, err)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if m.tokenStore.IsTokenBlacklisted(tokenString) {
				err := errors.New(errors.ErrCodeUnauthorized, "token is blacklisted")
				utils.WriteError(w, err)
				return
			}

			if m.tokenManager.IsTokenExpired(tokenString) {
				err := errors.New(errors.ErrCodeExpiredToken, "token is expired")
				utils.WriteError(w, err)
				return
			}

			_, err := m.tokenManager.ParseToken(tokenString)
			if err != nil {
				wrappedErr := errors.Wrap(err, errors.ErrCodeTokenParsing, "failed to parse token")
				utils.WriteError(w, wrappedErr)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RedirectToHTTPS is a middleware that redirects HTTP requests to HTTPS.
func (m *Middleware) RedirectToHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			redirectToHttps(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimit is a middleware that limits the number of requests based on the rate limiter.
func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.rateLimiter.Allow() {
			err := errors.New(errors.ErrCodeRequestLimitExceeded, "too many requests")
			utils.WriteError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// StrictRateLimit applies stricter rate limiting for sensitive operations.
func (m *Middleware) StrictRateLimit(next http.Handler) http.Handler {
	strictLimiter := NewRateLimiter(maxRequestsForStrictRateLimiting)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strictLimiter.Allow() {
			err := errors.New(errors.ErrCodeRequestLimitExceeded, "rate limit exceeded for sensitive operations")
			utils.WriteError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequiresContentType creates middleware that validates the request Content-Type header
// against the provided contentType (e.g., "application/json")
func (m *Middleware) RequiresContentType(contentType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}

			ct := r.Header.Get("Content-Type")
			if ct == "" {
				err := errors.New(errors.ErrCodeInvalidContentType, "Content-Type header is required")
				utils.WriteError(w, err)
				return
			}

			if !strings.HasPrefix(ct, contentType) {
				err := errors.New(
					errors.ErrCodeInvalidContentType,
					fmt.Sprintf("unsupported Content-Type, expected: %s", contentType),
				)
				utils.WriteError(w, err)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// redirectToHttps redirects an HTTP request to HTTPS.
func redirectToHttps(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	target := "https://" + host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}
