package domain

import (
	"context"
	"net/http"

	jwks "github.com/vigiloauth/vigilo/internal/domain/jwks"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
)

type OIDCService interface {
	// GetUserInfo retrieves the user's profile information based on the claims
	// extracted from a validated access token.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - accessTokenClaims *TokenClaims: A pointer to TokenClaims that were parsed and validated
	//     from the access token. These typically include standard OIDC claims such as
	//     'sub' (subject identifier), 'scope', 'exp' (expiration), etc.
	//   - r *http.Request: The HTTP request containing the cookies.
	//
	// Returns:
	//   - *UserInfoResponse: A pointer to a UserInfoResponse struct containing the requested user
	//     information (e.g., name, email, profile picture), filtered according to the
	//     authorized scopes.
	//   - error: An error if the user cannot be found, the scopes are insufficient, or any
	//     other issue occurs during retrieval.
	GetUserInfo(ctx context.Context, accessTokenClaims *token.TokenClaims, r *http.Request) (*user.UserInfoResponse, error)

	// GetJwks retrieves the JSON Web Key Set (JWKS) used for verifying signatures
	// of tokens issued by the OpenID Connect provider.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//
	// Returns:
	//   - *Jwks: A pointer to a Jwks struct containing the public keys in JWKS format.
	GetJwks(ctx context.Context) *jwks.Jwks
}
