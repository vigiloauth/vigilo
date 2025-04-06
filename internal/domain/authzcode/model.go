package domain

import "time"

// AuthorizationCodeData represents the data associated with an authorization code.
type AuthorizationCodeData struct {
	UserID              string
	ClientID            string
	RedirectURI         string
	Scope               string
	Code                string
	CreatedAt           time.Time
	Used                bool
	CodeChallenge       string
	CodeChallengeMethod string
}

const (
	S256  string = "SHA-256"
	Plain string = "plain"
)
