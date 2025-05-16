package domain

import (
	"net/http"
	"time"
)

// AuthorizationCodeData represents the data associated with an authorization code.
type AuthorizationCodeData struct {
	UserID                 string
	ClientID               string
	RedirectURI            string
	Scope                  string
	Code                   string
	CodeChallenge          string
	CodeChallengeMethod    string
	Nonce                  string
	AccessTokenHash        string
	Used                   bool
	CreatedAt              time.Time
	UserAuthenticationTime time.Time
	Request                *http.Request
}

const (
	S256  string = "SHA-256"
	Plain string = "plain"
)
