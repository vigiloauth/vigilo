package domain

import (
	"github.com/golang-jwt/jwt"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

// TokenData represents the data associated with a token.
type TokenData struct {
	Token       string       // The token string.
	ID          string       // The id associated with the token.
	ExpiresAt   int64        // The token's expiration time.
	TokenID     string       // The ID of the token.
	TokenClaims *TokenClaims // The claims associated with the token.
}

// TokenResponse represents the structure of an OAuth token response.
// This is returned to the client after successful authentication.
type TokenResponse struct {
	AccessToken  string      `json:"access_token"`
	RefreshToken string      `json:"refresh_token,omitempty"`
	TokenType    string      `json:"token_type"`
	IDToken      string      `json:"id_token"`
	Scope        types.Scope `json:"scope,omitempty"`
	ExpiresIn    int64       `json:"expires_in"`
}

type TokenIntrospectionResponse struct {
	Active          bool   `json:"active"`
	ExpiresAt       int64  `json:"exp,omitempty"`
	IssuedAt        int64  `json:"iat,omitempty"`
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
	Scopes          types.Scope           `json:"scopes,omitempty"`
	Roles           string                `json:"roles,omitempty"`
	Nonce           string                `json:"nonce,omitempty"`
	AuthTime        int64                 `json:"auth_time,omitempty"`
	RequestedClaims *domain.ClaimsRequest `json:"claims,omitempty"`
	ACRValues       string                `json:"acr,omitempty"`
	ClientID        string                `json:"client_id,omitempty"`
	RedirectURI     string                `json:"redirect_uri,omitempty"`
	State           string                `json:"state,omitempty"`
	*jwt.StandardClaims
}

const BearerToken string = "bearer"

func NewTokenIntrospectionResponse(claims *TokenClaims) *TokenIntrospectionResponse {
	response := &TokenIntrospectionResponse{
		ExpiresAt:       claims.StandardClaims.ExpiresAt,
		IssuedAt:        claims.StandardClaims.IssuedAt,
		Subject:         claims.StandardClaims.Subject,
		Issuer:          claims.StandardClaims.Issuer,
		TokenIdentifier: claims.StandardClaims.Id,
		Active:          true,
	}

	if claims.Audience != "" {
		response.Audience = claims.StandardClaims.Audience
	}

	return response
}
