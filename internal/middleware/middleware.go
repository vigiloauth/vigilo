package middleware

import (
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/utils"
)

type Middleware struct {
	serverConfig config.ServerConfig
	tokenService *token.TokenService
	rateLimiter  *RateLimiter
}

func NewMiddleware(serverConfig config.ServerConfig, tokenService *token.TokenService) *Middleware {
	return &Middleware{
		serverConfig: serverConfig,
		tokenService: tokenService,
		rateLimiter:  NewRateLimiter(serverConfig.MaxRequestsPerMinute()),
	}
}

// AuthMiddleware is a middleware that checks for a valid JWT token in the Authorization header.
func (m *Middleware) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				utils.WriteError(w, errors.NewInvalidCredentialsError())
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if token.GetTokenBlacklist().IsTokenBlacklisted(tokenString) {
				utils.WriteError(w, errors.NewInvalidCredentialsError())
				return
			}

			_, err := m.tokenService.ParseToken(tokenString)
			if err != nil {
				utils.WriteError(w, errors.NewInvalidCredentialsError())
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
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func redirectToHttps(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	target := "https://" + host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}
