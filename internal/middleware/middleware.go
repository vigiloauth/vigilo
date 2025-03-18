package middleware

import (
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// Middleware encapsulates middleware functionalities.
type Middleware struct {
	serverConfig *config.ServerConfig // Server configuration.
	tokenManager token.TokenManager   // Token manager for JWT operations.
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
func NewMiddleware(tokenManager token.TokenManager, tokenStore token.TokenStore) *Middleware {
	serverConfig := config.GetServerConfig()
	return &Middleware{
		serverConfig: serverConfig,
		tokenStore:   tokenStore,
		tokenManager: tokenManager,
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
		if r.TLS == nil {
			redirectToHttps(w, r)
			return
		}
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
		if !m.rateLimiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// redirectToHttps redirects an HTTP request to HTTPS.
//
// Parameters:
//
//	w http.ResponseWriter: The response writer.
//	r *http.Request: The request.
func redirectToHttps(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	target := "https://" + host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}
