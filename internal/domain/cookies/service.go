package domain

import (
	"net/http"
	"time"
)

type HTTPCookieService interface {
	// SetSessionCookie sets the session token in an HttpOnly cookie.
	// It also sets the cookie's expiration time and other attributes.
	//
	// Parameters:
	//
	//   - w http.ResponseWriter: The HTTP response writer.
	//   - token string: The session token to set in the cookie.
	//   - expirationTime time.Duration: The expiration time for the cookie.
	SetSessionCookie(w http.ResponseWriter, token string, expirationTime time.Duration)

	// ClearSessionCookie clears the session token cookie.
	//
	// Parameters:
	//
	//   - w http.ResponseWriter: The HTTP response writer.
	ClearSessionCookie(w http.ResponseWriter)

	// GetSessionToken retrieves the session token from the request's cookies.
	//
	// Parameters:
	//   - r *http.Request: The HTTP request containing the cookies.
	//
	// Returns:
	//
	//   - string: The session token if found, otherwise an empty string.
	//   - error: An error if retrieving the token fails.
	GetSessionToken(r *http.Request) (string, error)

	GetSessionCookie(r *http.Request) (*http.Cookie, error)
}
