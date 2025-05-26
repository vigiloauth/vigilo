package middleware

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	web "github.com/vigiloauth/vigilo/v2/internal/web"
)

const maxRequestsForStrictRateLimiting int = 3

// Middleware encapsulates middleware functionalities.
type Middleware struct {
	tokenParser    token.TokenParser
	tokenValidator token.TokenValidator
	serverConfig   *config.ServerConfig
	rateLimiter    *RateLimiter

	logger *config.Logger
	module string
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func NewMiddleware(
	tokenParser token.TokenParser,
	tokenValidator token.TokenValidator,
) *Middleware {
	serverConfig := config.GetServerConfig()
	return &Middleware{
		tokenParser:    tokenParser,
		tokenValidator: tokenValidator,
		serverConfig:   serverConfig,
		rateLimiter:    NewRateLimiter(serverConfig.MaxRequestsPerMinute()),
		logger:         serverConfig.Logger(),
		module:         "Middleware",
	}
}

// AuthMiddleware is a middleware that checks for a valid JWT token in the Authorization header or POST body.
func (m *Middleware) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestID := utils.GetRequestID(ctx)

			var tokenString string
			var authHeaderErr error

			tokenString, authHeaderErr = web.ExtractBearerToken(r)

			if r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
				m.logger.Debug(m.module, requestID, "[AuthMiddleware]: Bearer token not found in header, attempting to check POST body for access_token parameter.")
				parseErr := r.ParseForm()
				if parseErr != nil {
					m.logger.Warn(m.module, requestID, "[AuthMiddleware]: Failed to parse form body: %v", parseErr)
					wrappedErr := errors.Wrap(parseErr, errors.ErrCodeInvalidRequest, "failed to parse request body")
					web.WriteError(w, wrappedErr)
					return
				}

				bodyToken := r.Form.Get(constants.AccessTokenPost)
				if bodyToken != "" {
					m.logger.Debug(m.module, requestID, "[AuthMiddleware]: Found access_token in POST body.")
					tokenString = bodyToken
				} else {
					m.logger.Warn(m.module, requestID, "[AuthMiddleware]: Access token not found in header or POST body.")
					err := errors.New(errors.ErrCodeUnauthorized, "missing or invalid access token")
					web.WriteError(w, err)
					return
				}
			} else if authHeaderErr != nil {
				m.logger.Warn(m.module, requestID, "[AuthMiddleware]: Access token not found in header, and POST body check conditions not met or token not found in body.")
				wrappedErr := errors.Wrap(authHeaderErr, errors.ErrCodeUnauthorized, "missing or invalid authorization header")
				web.WriteError(w, wrappedErr)
				return
			}

			if tokenString == "" {
				m.logger.Warn(m.module, requestID, "[AuthMiddleware]: tokenString is empty after all extraction attempts.")
				wrappedErr := errors.New(errors.ErrCodeUnauthorized, "missing or invalid access token after extraction attempts")
				web.WriteError(w, wrappedErr)
				return
			}

			claims, parseErr := m.tokenParser.ParseToken(ctx, tokenString)
			if parseErr != nil {
				m.logger.Warn(m.module, requestID, "[AuthMiddleware]: Failed to parse token: %s", parseErr)
				wrappedErr := errors.Wrap(parseErr, errors.ErrCodeTokenParsing, "failed to parse token")
				web.WriteError(w, wrappedErr)
				return
			}

			m.logger.Debug(m.module, requestID, "[AuthMiddleWare]: Attempting to validate token")
			if validateErr := m.tokenValidator.ValidateToken(ctx, tokenString); validateErr != nil {
				m.logger.Warn(m.module, requestID, "[AuthMiddleware]: Failed to validate token: %s", validateErr)
				wrappedErr := errors.Wrap(validateErr, errors.ErrCodeUnauthorized, "an error occurred validating the access token")
				web.WriteError(w, wrappedErr)
				return
			}

			ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyTokenClaims, claims)
			ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyAccessToken, tokenString)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (m *Middleware) RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		clientIP := r.RemoteAddr
		if forwarderFor := r.Header.Get(constants.XForwardedHeader); forwarderFor != "" {
			clientIP = strings.Split(forwarderFor, ",")[0]
		}

		authHeader := r.Header.Get(constants.AuthorizationHeader)
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) > 1 {
				authHeader = fmt.Sprintf("%s:%s", parts[0], parts[1])
			}
		}

		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200 OK
		}

		next.ServeHTTP(wrappedWriter, r)
		duration := time.Since(startTime)
		userAgent := r.Header.Get("User-Agent")

		m.logger.Debug(m.module, utils.GetRequestID(r.Context()),
			"Method=[%s] | URL=[%s] | Status=[%d] | IP=[%s] | Duration=[%v] | User-Agent=[%s] | Auth=[%v]",
			r.Method, r.URL.Path, wrappedWriter.statusCode, clientIP, duration, userAgent, authHeader != "",
		)
	})
}

// WithRole is a middleware that checks if an access token has sufficient privileges to access resources.
func (m *Middleware) WithRole(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestID := utils.GetRequestID(ctx)

			var claims *token.TokenClaims
			if val := utils.GetValueFromContext(ctx, constants.ContextKeyTokenClaims); val != nil {
				claims, _ = val.(*token.TokenClaims)
			} else {
				m.logger.Error(m.module, requestID, "[WithRole]: An error occurred accessing token from context")
				web.WriteError(w, errors.NewInternalServerError())
				return
			}

			roles := strings.Split(claims.Roles, " ")
			hasRole := slices.Contains(roles, requiredRole)
			if !hasRole {
				err := errors.New(errors.ErrCodeInsufficientRole, "the request requires higher privileges than provided by the access token")
				web.WriteError(w, err)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RedirectToHTTPS is a middleware that redirects HTTP requests to HTTPS.
func (m *Middleware) RedirectToHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestID := utils.GetRequestID(ctx)

		if r.TLS == nil {
			m.logger.Debug(m.module, requestID, "[RedirectToHTTPS]: Redirecting request to HTTPS")
			redirectToHttps(w, r)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RateLimit is a middleware that limits the number of requests based on the rate limiter.
func (m *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestID := utils.GetRequestID(ctx)

		if !m.rateLimiter.Allow(requestID) {
			m.logger.Warn(m.module, requestID, "[RateLimit]: Rate limit exceeded for url=[%s]", r.URL.Path)
			err := errors.New(errors.ErrCodeRequestLimitExceeded, "too many requests")
			web.WriteError(w, err)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// StrictRateLimit applies stricter rate limiting for sensitive operations.
func (m *Middleware) StrictRateLimit(next http.Handler) http.Handler {
	strictLimiter := NewRateLimiter(maxRequestsForStrictRateLimiting)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestID := utils.GetRequestID(ctx)

		if !strictLimiter.Allow(requestID) {
			m.logger.Warn(m.module, requestID, "[StrictRateLimit]: Strict rate limit exceeded for url=[%s]", r.URL.Path)
			err := errors.New(errors.ErrCodeRequestLimitExceeded, "rate limit exceeded for sensitive operations")
			web.WriteError(w, err)
			return
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRequestMethod checks to see if a request method is valid for a request
func (m *Middleware) RequireRequestMethod(requestMethod string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestID := utils.GetRequestID(ctx)

			if r.Method != requestMethod {
				m.logger.Warn(m.module, requestID, "[RequireRequestMethod]: Invalid request method received for url=%s", r.URL.Path)
				err := errors.New(errors.ErrCodeMethodNotAllowed, fmt.Sprintf("method %s not allowed for this request", r.Method))
				web.WriteError(w, err)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// WithContextValues ensures each request has contains a request ID, the UserAgent, remote address, and the header.
func (m *Middleware) WithContextValues(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		requestID := r.Header.Get(constants.RequestIDHeader)
		if requestID == "" {
			requestID = constants.RequestIDPrefix + utils.GenerateUUID()
		}
		w.Header().Set(constants.RequestIDHeader, requestID)

		ipAddress := r.RemoteAddr
		if forwardedFor := r.Header.Get(constants.XForwardedHeader); forwardedFor != "" {
			ipAddress = forwardedFor
		}

		ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyIPAddress, ipAddress)
		ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyRequestID, requestID)
		ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserAgent, r.UserAgent())

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequiresContentType creates middleware that validates the request Content-Type header
// against the provided contentType (e.g., "application/json")
func (m *Middleware) RequiresContentType(contentType string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			requestID := utils.GetRequestID(ctx)

			if r.Method == http.MethodOptions {
				m.logger.Debug(m.module, requestID, "[RequiresContentType]: Passing request to next handler")
				next.ServeHTTP(w, r)
				return
			}

			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				m.logger.Debug(m.module, requestID, "[RequiresContentType]: Passing request to next handler")
				next.ServeHTTP(w, r)
				return
			}

			ct := r.Header.Get("Content-Type")
			if ct == "" {
				m.logger.Warn(m.module, requestID, "[RequiresContentType]: Content-Type header is missing in request")
				err := errors.New(errors.ErrCodeInvalidContentType, "Content-Type header is required")
				web.WriteError(w, err)
				return
			}

			if !strings.HasPrefix(ct, contentType) {
				err := errors.New(
					errors.ErrCodeInvalidContentType,
					fmt.Sprintf("unsupported Content-Type, expected: %s", contentType),
				)
				m.logger.Warn(m.module, requestID, "[RequiresContentType]: Unsupported Content-Type=[%s] received for request", contentType)
				web.WriteError(w, err)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
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
