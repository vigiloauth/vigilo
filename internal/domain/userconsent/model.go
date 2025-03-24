package domain

import "time"

// ConsentRecord represents a user's consent for a specific client
type ConsentRecord struct {
	UserID    string
	ClientID  string
	Scope     string
	CreatedAt time.Time
}

type ConsentResponse struct {
	ClientID        string   `json:"client_id"`
	ClientName      string   `json:"client_name"`
	RedirectURI     string   `json:"redirect_uri"`
	Scopes          []string `json:"scopes"`
	ConsentEndpoint string   `json:"consent_endpoint"`
}

type ConsentRequest struct {
	Approved bool     `json:"approved"`
	Scopes   []string `json:"scopes,omitempty"`
}

type ConsentDenialResponse struct {
	Error       string `json:"error"`
	RedirectURL string `json:"redirect_url"`
}

type ConsentSuccessResponse struct {
	Success     bool   `json:"success"`
	RedirectURL string `json:"redirect_url"`
}

type ConsentErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ConsentURL       string `json:"consent_url"`
}
