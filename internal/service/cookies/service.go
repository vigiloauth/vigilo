package service

import (
	"context"
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	cookies "github.com/vigiloauth/vigilo/internal/domain/cookies"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
)

var _ cookies.HTTPCookieService = (*httpCookieService)(nil)

type httpCookieService struct {
	sessionCookieName string
	logger            *config.Logger
	module            string
}

func NewHTTPCookieService() cookies.HTTPCookieService {
	return &httpCookieService{
		sessionCookieName: config.GetServerConfig().SessionCookieName(),
		logger:            config.GetServerConfig().Logger(),
		module:            "HTTP Cookie Service",
	}
}

// SetSessionCookie sets the session token in an HttpOnly cookie.
// It also sets the cookie's expiration time and other attributes.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - w http.ResponseWriter: The HTTP response writer.
//   - token string: The session token to set in the cookie.
//   - expirationTime time.Duration: The expiration time for the cookie.
func (c *httpCookieService) SetSessionCookie(ctx context.Context, w http.ResponseWriter, token string, expirationTime time.Duration) {
	requestID := utils.GetRequestID(ctx)

	shouldUseHTTPS := config.GetServerConfig().ForceHTTPS()
	c.logger.Info(c.module, requestID, "[SetSessionCookie]: Setting session cookie with name=[%s], expiration=[%s], token[%s]",
		utils.TruncateSensitive(c.sessionCookieName),
		expirationTime,
		utils.TruncateSensitive(token),
	)

	http.SetCookie(w, &http.Cookie{
		Name:     c.sessionCookieName,
		Value:    token,
		Expires:  time.Now().Add(expirationTime),
		HttpOnly: true,
		Secure:   shouldUseHTTPS,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearSessionCookie clears the session token cookie.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - w http.ResponseWriter: The HTTP response writer.
func (c *httpCookieService) ClearSessionCookie(ctx context.Context, w http.ResponseWriter) {
	requestID := utils.GetRequestID(ctx)

	c.logger.Info(c.module, requestID, "[ClearSessionCookie]: Clearing session cookie for [%s]", utils.TruncateSensitive(c.sessionCookieName))
	http.SetCookie(w, &http.Cookie{
		Name:     c.sessionCookieName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// GetSessionToken retrieves the session token from the request's cookies.
//
// Parameters:
//   - r *http.Request: The HTTP request containing the cookies.
//
// Returns:
//   - string: The session token if found, otherwise an empty string.
//   - error: An error if retrieving the token fails.
func (c *httpCookieService) GetSessionToken(r *http.Request) (string, error) {
	requestID := utils.GetRequestID(r.Context())
	cookie, err := r.Cookie(c.sessionCookieName)
	if err != nil {
		c.logger.Error(c.module, requestID, "[GetSessionToken]: Failed to retrieve session token: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeMissingHeader, "session token not found")
	}

	return cookie.Value, nil
}

// GetSessionToken retrieves the session cookie from the request.
//
// Parameters:
//   - r *http.Request: The HTTP request containing the session.
//
// Returns:
//   - string: The session cookie if found, otherwise nil.
//   - error: An error if retrieving the cookie fails.
func (c *httpCookieService) GetSessionCookie(r *http.Request) (*http.Cookie, error) {
	requestID := utils.GetRequestID(r.Context())
	cookie, err := r.Cookie(c.sessionCookieName)
	if err != nil {
		c.logger.Error(c.module, requestID, "[GetSessionCookie]: Failed to retrieve session cookie: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeMissingHeader, "failed to retrieve cookie from request")
	}

	return cookie, nil
}
