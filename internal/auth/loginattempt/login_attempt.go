package auth

import "time"

// maxStoredLoginAttempts defines the maximum number of login attempts stored per user.
const maxStoredLoginAttempts = 100

// LoginAttempt represents a single login attempt.
type LoginAttempt struct {
	UserID          string    // UserID associated with the login attempt.
	IPAddress       string    // IP address from which the login attempt was made.
	Timestamp       time.Time // Timestamp of the login attempt.
	RequestMetadata string    // Additional request metadata (e.g., headers).
	Details         string    // Details about the login attempt (e.g., error messages).
	UserAgent       string    // User agent of the client making the login attempt.
	FailedAttempts  int       // Number of failed attempts (if applicable).
}
