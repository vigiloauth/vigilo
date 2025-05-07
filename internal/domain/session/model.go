package domain

import "time"

// SessionData represents the data stored for a user's session.
type SessionData struct {
	ID                 string    // ID of the session.
	UserID             string    // ID of the user associated with the session.
	State              string    // Random string used to prevent CSRF attacks during Authorization Flow.
	ClientID           string    // ID of the OAuth 2.0 client application.
	UserIPAddress      string    // IP address of the user at the time of session creation.
	UserAgent          string    // User agent string of the user's browser or device.
	RedirectURI        string    // Redirect URI from OAuth 2.0 client application.
	ExpirationTime     time.Time // The timestamp when the session expires.
	AuthenticationTime time.Time // The timestamp of when the user was last authenticated
}
