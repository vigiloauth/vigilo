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
}

type UserConsentRequest struct {
	Approved bool     `json:"approved"`
	Scopes   []string `json:"scopes,omitempty"`
}

type UserConsentDenialResponse struct {
	Error       string `json:"error"`
	RedirectURL string `json:"redirect_url"`
}

type UserConsentSuccessResponse struct {
	Success     bool   `json:"success"`
	RedirectURL string `json:"redirect_url"`
}
