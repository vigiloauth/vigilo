package domain

import "time"

// UserConsentRecord represents a user's consent for a specific client
type UserConsentRecord struct {
	UserID    string
	ClientID  string
	Scope     string
	CreatedAt time.Time
}

type UserConsentResponse struct {
	ClientID        string   `json:"client_id"`
	ClientName      string   `json:"client_name"`
	RedirectURI     string   `json:"redirect_uri"`
	Scopes          []string `json:"scopes"`
	ConsentEndpoint string   `json:"consent_endpoint"`
	State           string   `json:"state"`
	Error           string   `json:"error,omitempty"`
	Success         bool     `json:"success,omitempty"`
}

type UserConsentRequest struct {
	Approved     bool     `json:"approved"`
	Scopes       []string `json:"scopes,omitempty"`
	ResponseType string
	State        string
	Nonce        string
	Display      string
}
