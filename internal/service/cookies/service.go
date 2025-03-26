package service

import (
	"net/http"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	cookies "github.com/vigiloauth/vigilo/internal/domain/cookies"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ cookies.HTTPCookieService = (*HTTPCookieServiceImpl)(nil)

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
		return "", errors.Wrap(err, errors.ErrCodeMissingHeader, "session cookie not found")
	}
	return cookie.Value, nil
}
