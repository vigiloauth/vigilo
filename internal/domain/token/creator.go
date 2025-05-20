package domain

import (
	"context"
	"time"

	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

type TokenCreator interface {
	// CreateAccessToken generates an access token for the given subject and expiration time.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - subject string: The subject of the token (e.g., user email).
	//   - audience string: The audience of the token (e.g., client ID).
	// 	 - scopes types.Scope: The scopes to be added to the token (can be an empty string if none are needed)..
	//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
	//   - nonce string: A random string used to prevent replay attacks provided by the client.
	//
	// Returns:
	//   - string: The generated JWT token string.
	//   - error: An error if token generation fails.
	CreateAccessToken(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error)

	// CreateRefreshToken generates an access token for the given subject and expiration time.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - subject string: The subject of the token (e.g., user email).
	//   - audience string: The audience of the token (e.g., client ID).
	// 	 - scopes types.Scope: The scopes to be added to the token (can be an empty string if none are needed)..
	//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
	//   - nonce string: A random string used to prevent replay attacks provided by the client.
	//
	// Returns:
	//   - string: The generated JWT token string.
	//   - error: An error if token generation fails.
	CreateRefreshToken(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error)

	// CreateAccessTokenWithClaims generates an access token for the given subject and expiration time.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - subject string: The subject of the token (e.g., user email).
	//   - audience string: The audience of the token (e.g., client ID).
	// 	 - scopes types.Scope: The scopes to be added to the token (can be an empty string if none are needed)..
	//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
	//   - nonce string: A random string used to prevent replay attacks provided by the client.
	//	 - requestedClaims *claims.ClaimsRequest: The requested claims
	//
	// Returns:
	//   - string: The generated JWT token string.
	//   - error: An error if token generation fails.
	CreateAccessTokenWithClaims(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string, requestedClaims *claims.ClaimsRequest) (string, error)

	// CreateIDToken creates an ID token for the specified user and client.
	//
	// The ID token is a JWT that contains claims about the authentication of the user.
	// It includes information such as the user ID, client ID, scopes, and nonce for
	// replay protection. The token is generated and then stored in the token store.
	//
	// Parameters:
	//   - ctx context.Context: Context for the request, containing the request ID for logging.
	//   - userID string: The unique identifier of the user.
	//   - clientID string: The client application identifier requesting the token.
	//   - scopes string: Space-separated list of requested scopes.
	//   - nonce string: A random string used to prevent replay attacks.
	//   - authTime *Time: Time at which the user was authenticated. The value of time can be nil as it only applies when a request with "max_age" was given
	//
	// Returns:
	//   - string: The signed ID token as a JWT string.
	//   - error: An error if token generation fails.
	CreateIDToken(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, authTime time.Time) (string, error)
}
