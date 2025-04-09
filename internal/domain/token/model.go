package domain

import "time"

// TokenData represents the data associated with a token.
type TokenData struct {
	Token     string    // The token string.
	ID        string    // The id associated with the token.
	ExpiresAt time.Time // The token's expiration time.
	TokenID   string
}

// TokenResponse represents the structure of an OAuth token response.
// This is returned to the client after successful authentication.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type TokenRequest struct {
	GrantType         string `json:"grant_type"`
	AuthorizationCode string `json:"code"`
	RedirectURI       string `json:"redirect_uri"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	State             string `json:"state"`
	CodeVerifier      string `json:"code_verifier,omitempty"`
}

const BearerToken string = "Bearer"
