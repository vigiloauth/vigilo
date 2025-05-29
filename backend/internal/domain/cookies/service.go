package domain

import (
	"context"
	"net/http"
	"time"
)

type HTTPCookieService interface {
	// SetSessionCookie sets the session token in an HttpOnly cookie.
	// It also sets the cookie's expiration time and other attributes.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//  - w http.ResponseWriter: The HTTP response writer.
	//  - sessionID string: The session ID to set in the cookie.
	//  - expirationTime time.Duration: The expiration time for the cookie.
	SetSessionCookie(ctx context.Context, w http.ResponseWriter, sessionID string, expirationTime time.Duration)

	// ClearSessionCookie clears the session token cookie.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//  - w http.ResponseWriter: The HTTP response writer.
	ClearSessionCookie(ctx context.Context, w http.ResponseWriter)

	// GetSessionToken retrieves the session cookie from the request.
	//
	// Parameters:
	//  - r *http.Request: The HTTP request containing the session.
	//
	// Returns:
	//  - string: The session cookie if found, otherwise nil.
	//  - error: An error if retrieving the cookie fails.
	GetSessionCookie(r *http.Request) (*http.Cookie, error)
}
