package service

import (
	"context"
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	cookies "github.com/vigiloauth/vigilo/v2/internal/domain/cookies"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ cookies.HTTPCookieService = (*httpCookieService)(nil)

type httpCookieService struct {
	sessionCookieName string
	domain            string
	enableHTTPS       bool

	logger *config.Logger
	module string
}

func NewHTTPCookieService() cookies.HTTPCookieService {
	return &httpCookieService{
		sessionCookieName: config.GetServerConfig().SessionCookieName(),
		domain:            config.GetServerConfig().Domain(),
		enableHTTPS:       config.GetServerConfig().ForceHTTPS(),
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
//   - sessionID string: The session ID to set in the cookie.
//   - expirationTime time.Duration: The expiration time for the cookie.
func (c *httpCookieService) SetSessionCookie(ctx context.Context, w http.ResponseWriter, sessionID string, expirationTime time.Duration) {
	requestID := utils.GetRequestID(ctx)
	c.logger.Debug(c.module, requestID, "[SetSessionCookie]: Setting session cookie with ID=[%s], expiration=[%s], HTTPS=[%t]",
		sessionID,
		expirationTime,
		c.enableHTTPS,
	)

	sameSiteMode, secureFlag := c.getCookieSecuritySettings()
	http.SetCookie(w, &http.Cookie{
		Name:     c.sessionCookieName,
		Value:    sessionID,
		Expires:  time.Now().Add(expirationTime),
		HttpOnly: true,
		Secure:   secureFlag,
		SameSite: sameSiteMode,
		Path:     "/",
		Domain:   c.domain,
	})
}

// ClearSessionCookie clears the session token cookie.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - w http.ResponseWriter: The HTTP response writer.
func (c *httpCookieService) ClearSessionCookie(ctx context.Context, w http.ResponseWriter) {
	requestID := utils.GetRequestID(ctx)
	c.logger.Debug(c.module, requestID, "[ClearSessionCookie]: Clearing session cookie for [%s]", c.sessionCookieName)

	sameSiteMode, secureFlag := c.getCookieSecuritySettings()
	http.SetCookie(w, &http.Cookie{
		Name:     c.sessionCookieName,
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
		Secure:   secureFlag,
		SameSite: sameSiteMode,
		Path:     "/",
		Domain:   c.domain,
	})
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
	c.logger.Debug(c.module, requestID, "[GetSessionCookie]: Attempting to retrieve session cookie")

	cookie, err := r.Cookie(c.sessionCookieName)
	if err != nil {
		c.logger.Error(c.module, requestID, "[GetSessionCookie]: Failed to retrieve session cookie: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeMissingHeader, "failed to retrieve cookie from request")
	}

	return cookie, nil
}

func (c *httpCookieService) getCookieSecuritySettings() (http.SameSite, bool) {
	if c.enableHTTPS {
		return http.SameSiteNoneMode, true
	}

	return http.SameSiteStrictMode, false
}
