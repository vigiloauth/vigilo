package token

// TokenResponse represents the structure of an OAuth token response.
// This is returned to the client after successful authentication.
type TokenResponse struct {
	AccessToken string `json:"access_token"`    // The token that must be used for authenticated requests.
	TokenType   string `json:"token_type"`      // The type of token (e.g., "Bearer").
	ExpiresIn   int    `json:"expires_in"`      // The duration in seconds until the token expires.
	Scope       string `json:"scope,omitempty"` // The scope of access granted with the token.
}

const BearerToken string = "Bearer"
