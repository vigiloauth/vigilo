package domain

import "time"

// AuthorizationCodeData represents the data associated with an authorization code.
type AuthorizationCodeData struct {
	UserID      string
	ClientID    string
	RedirectURI string
	Scope       string
	Code        string
	CreatedAt   time.Time
	Used        bool
}
