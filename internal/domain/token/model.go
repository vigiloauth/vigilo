package domain

import (
	"time"

	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// TokenData represents the data associated with a token.
type TokenData struct {
	Token     string    // The token string.
	ID        string    // The id associated with the token.
	ExpiresAt time.Time // The token's expiration time.
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
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	State        string `json:"state"`
}

const BearerToken string = "Bearer"

func (t *TokenRequest) Validate() error {
	if t.GrantType != client.AuthorizationCode {
		return errors.New(errors.ErrCodeInvalidGrant, "invalid grant_type")
	}
	if t.Code == "" || t.RedirectURI == "" || t.ClientID == "" || t.ClientSecret == "" || t.State == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "missing required parameters")
	}

	return nil
}
