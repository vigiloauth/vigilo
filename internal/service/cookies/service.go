package service

import (
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	cookies "github.com/vigiloauth/vigilo/internal/domain/cookies"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ cookies.HTTPCookieService = (*HTTPCookieServiceImpl)(nil)
var logger = config.GetServerConfig().Logger()

const module = "HTTPCookieService"

type HTTPCookieServiceImpl struct {
	sessionCookieName string
}

func NewHTTPCookieServiceImpl() *HTTPCookieServiceImpl {
	return &HTTPCookieServiceImpl{
		sessionCookieName: config.GetServerConfig().SessionCookieName(),
	}
}

// SetSessionCookie sets the session token in an HttpOnly cookie.
// It also sets the cookie's expiration time and other attributes.
//
// Parameters:
//
//   - w http.ResponseWriter: The HTTP response writer.
//   - token string: The session token to set in the cookie.
//   - expirationTime time.Duration: The expiration time for the cookie.
//
// Returns:
//
//   - error: An error if setting the cookie fails.
func (c *HTTPCookieServiceImpl) SetSessionCookie(w http.ResponseWriter, token string, expirationTime time.Duration) {
	shouldUseHTTPS := config.GetServerConfig().ForceHTTPS()
	logger.Info(module, "SetSessionCookie: Setting session cookie with name=[%s], expiration=[%s], token[%s]",
		common.TruncateSensitive(c.sessionCookieName),
		expirationTime,
		common.TruncateSensitive(token),
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
//
//   - w http.ResponseWriter: The HTTP response writer.
func (c *HTTPCookieServiceImpl) ClearSessionCookie(w http.ResponseWriter) {
	logger.Info(module, "ClearSessionCookie: Clearing session cookie for [%s]", common.TruncateSensitive(c.sessionCookieName))
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
//
//   - string: The session token if found, otherwise an empty string.
//   - error: An error if retrieving the token fails.
func (c *HTTPCookieServiceImpl) GetSessionToken(r *http.Request) (string, error) {
	cookie, err := r.Cookie(c.sessionCookieName)
	if err != nil {
		logger.Error(module, "GetSessionToken: Failed to retrieve session token: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeMissingHeader, "session token not found")
	}
	return cookie.Value, nil
}

func (c *HTTPCookieServiceImpl) GetSessionCookie(r *http.Request) (*http.Cookie, error) {
	cookie, err := r.Cookie(c.sessionCookieName)
	if err != nil {
		logger.Error(module, "GetSessionCookie: Failed to retrieve session cookie: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeMissingHeader, "failed to retrieve cookie from request")
	}
	return cookie, nil
}
