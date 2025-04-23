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
	//  - token string: The session token to set in the cookie.
	//  - expirationTime time.Duration: The expiration time for the cookie.
	SetSessionCookie(ctx context.Context, w http.ResponseWriter, token string, expirationTime time.Duration)

	// ClearSessionCookie clears the session token cookie.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//  - w http.ResponseWriter: The HTTP response writer.
	ClearSessionCookie(ctx context.Context, w http.ResponseWriter)

	// GetSessionToken retrieves the session token from the request's cookies.
	//
	// Parameters:
	//  - r *http.Request: The HTTP request containing the cookies.
	//
	// Returns:
	//  - string: The session token if found, otherwise an empty string.
	//  - error: An error if retrieving the token fails.
	GetSessionToken(r *http.Request) (string, error)

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
