package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/crypto"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	web "github.com/vigiloauth/vigilo/internal/web"
)

var logger = config.GetServerConfig().Logger()

type contextKey string

const (
	module                           string = "Middleware"
	maxRequestsForStrictRateLimiting int    = 3
)

// Middleware encapsulates middleware functionalities.
type Middleware struct {
	serverConfig *config.ServerConfig
	tokenService token.TokenService
	rateLimiter  *RateLimiter
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
func NewMiddleware(tokenService token.TokenService) *Middleware {
	serverConfig := config.GetServerConfig()
	return &Middleware{
		serverConfig: serverConfig,
		tokenService: tokenService,
		rateLimiter:  NewRateLimiter(serverConfig.MaxRequestsPerMinute()),
	}
}

// AuthMiddleware is a middleware that checks for a valid JWT token in the Authorization header.
//
// Returns:
//
//	func(http.Handler) http.Handler: A middleware function.
func (m *Middleware) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug(module, "AuthMiddleware: Processing request method=%s url=%s", r.Method, r.URL.Path)

			tokenString, err := web.ExtractBearerToken(r)
			if err != nil {
				logger.Warn(module, "AuthMiddleware: Failed to extract bearer token: %v", err)
				wrappedErr := errors.Wrap(err, "", "failed to extract bearer token from authorization header")
				web.WriteError(w, wrappedErr)
				return
			}

			if err := m.tokenService.ValidateToken(tokenString); err != nil {
				logger.Warn(module, "AuthMiddleware: Failed to validate token: %s", err)
				wrappedErr := errors.Wrap(err, errors.ErrCodeUnauthorized, "an error occurred validating the access token")
				web.WriteError(w, wrappedErr)
				return
			}

			_, err = m.tokenService.ParseToken(tokenString)
			if err != nil {
				logger.Warn(module, "AuthMiddleware: Failed to parse token: %s", err)
				wrappedErr := errors.Wrap(err, errors.ErrCodeTokenParsing, "failed to parse token")
				web.WriteError(w, wrappedErr)
				return
			}

			logger.Debug(module, "AuthMiddleware: Token validated successfully, passing request to next handler")
			next.ServeHTTP(w, r)
		})
	}
}

// RedirectToHTTPS is a middleware that redirects HTTP requests to HTTPS.
//
// Parameters:
//
//	next http.Handler: The next handler in the chain.
//
// Returns:
//
//	http.Handler: A middleware handler.
func (m *Middleware) RedirectToHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug(module, "RedirectToHTTPS: Processing request method=%s url=%s", r.Method, r.URL.Path)
		if r.TLS == nil {
			logger.Debug(module, "RedirectToHTTPS: Redirecting request to HTTPS")
			redirectToHttps(w, r)
			return
		}

		logger.Debug(module, "RedirectToHTTPS: Passing request to next handler")
		next.ServeHTTP(w, r)
	})
}

// RateLimit is a middleware that limits the number of requests based on the rate limiter.
//
// Parameters:
//
//	next http.Handler: The next handler in the chain.
//
// Returns:
//
//	http.Handler: A middleware handler.
func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug(module, "RateLimit: Applying rate limiting to request method=%s url=%s", r.Method, r.URL.Path)
		if !m.rateLimiter.Allow() {
			logger.Warn(module, "RateLimit: Rate limit exceeded for url=%s", r.URL.Path)
			err := errors.New(errors.ErrCodeRequestLimitExceeded, "too many requests")
			web.WriteError(w, err)
			return
		}

		logger.Debug(module, "RateLimit: Passing request to next handler")
		next.ServeHTTP(w, r)
	})
}

// StrictRateLimit applies stricter rate limiting for sensitive operations.
func (m *Middleware) StrictRateLimit(next http.Handler) http.Handler {
	strictLimiter := NewRateLimiter(maxRequestsForStrictRateLimiting)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug(module, "StrictRateLimit: Applying strict rate limiting to request method=%s url=%s", r.Method, r.URL.Path)
		if !strictLimiter.Allow() {
			logger.Warn(module, "StrictRateLimit: Strict rate limit exceeded for url=%s", r.URL.Path)
			err := errors.New(errors.ErrCodeRequestLimitExceeded, "rate limit exceeded for sensitive operations")
			web.WriteError(w, err)
			return
		}

		logger.Debug(module, "StrictRateLimit: Passing request to next handler")
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) RequireRequestMethod(requestMethod string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug(module, "RequireRequestMethod: Validating request method=%s for url=%s", r.Method, r.URL.Path)
			if r.Method != requestMethod {
				logger.Warn(module, "RequireRequestMethod: Invalid request method received for url=%s", r.URL.Path)
				err := errors.New(errors.ErrCodeMethodNotAllowed, fmt.Sprintf("method '%s' not allowed for this request", r.Method))
				web.WriteError(w, err)
				return
			}

			logger.Debug(module, "RequireRequestMethod: Passing request to next handler")
			next.ServeHTTP(w, r)
		})
	}
}

// RequestIDMiddleware ensures each request has a unique request ID.
func (m *Middleware) RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(common.RequestIDHeader)
		if requestID == "" {
			requestID = crypto.GenerateUUID()
		}

		w.Header().Set(common.RequestIDHeader, requestID)
		ctx := context.WithValue(r.Context(), common.RequestID, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequiresContentType creates middleware that validates the request Content-Type header
// against the provided contentType (e.g., "application/json")
func (m *Middleware) RequiresContentType(contentType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug(module, "RequiresContentType: Validating content type=%s for url=%s", contentType, r.URL.Path)
			if r.Method == http.MethodOptions {
				logger.Debug(module, "RequiresContentType: Passing request to next handler")
				next.ServeHTTP(w, r)
				return
			}

			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				logger.Debug(module, "RequiresContentType: Passing request to next handler")
				next.ServeHTTP(w, r)
				return
			}

			ct := r.Header.Get("Content-Type")
			if ct == "" {
				logger.Warn(module, "RequiresContentType: Content-Type header is missing in request")
				err := errors.New(errors.ErrCodeInvalidContentType, "Content-Type header is required")
				web.WriteError(w, err)
				return
			}

			if !strings.HasPrefix(ct, contentType) {
				err := errors.New(
					errors.ErrCodeInvalidContentType,
					fmt.Sprintf("unsupported Content-Type, expected: %s", contentType),
				)
				logger.Warn(module, "RequiresContentType: Unsupported Content-Type=%s received for request", contentType)
				web.WriteError(w, err)
				return
			}

			logger.Debug(module, "RequiresContentType: Passing request to next handler")
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
