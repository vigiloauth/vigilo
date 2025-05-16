package domain

import (
	"time"

	"github.com/golang-jwt/jwt"
)

// TokenData represents the data associated with a token.
type TokenData struct {
	Token     string    // The token string.
	ID        string    // The id associated with the token.
	ExpiresAt time.Time // The token's expiration time.
	TokenID   string
	Claims    *TokenClaims
}

// TokenResponse represents the structure of an OAuth token response.
// This is returned to the client after successful authentication.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type TokenIntrospectionResponse struct {
	Active          bool   `json:"active"`
	ExpiresAt       int    `json:"exp,omitempty"`
	IssuedAt        int    `json:"iat,omitempty"`
	Subject         string `json:"subject,omitempty"`
	Audience        string `json:"aud,omitempty"`
	Issuer          string `json:"iss,omitempty"`
	TokenIdentifier string `json:"jti,omitempty"`
}

type TokenRequest struct {
	GrantType         string `json:"grant_type"`
	AuthorizationCode string `json:"code"`
	RedirectURI       string `json:"redirect_uri"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	State             string `json:"state"`
	CodeVerifier      string `json:"code_verifier,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
}

type TokenClaims struct {
	Scopes   string `json:"scopes,omitempty"`
	Roles    string `json:"roles,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	AuthTime int64  `json:"auth_time,omitempty"`
	*jwt.StandardClaims
}

const BearerToken string = "bearer"

func NewTokenIntrospectionResponse(claims *TokenClaims) *TokenIntrospectionResponse {
	response := &TokenIntrospectionResponse{
		ExpiresAt:       int(claims.ExpiresAt),
		IssuedAt:        int(claims.IssuedAt),
		Subject:         claims.Subject,
		Issuer:          claims.Issuer,
		TokenIdentifier: claims.Id,
	}

	if claims.Audience != "" {
		response.Audience = claims.Audience
	}

	return response
}
