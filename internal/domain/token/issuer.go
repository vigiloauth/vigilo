package domain

import (
	"context"
	"time"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

// TokenIssuer defines an interface for issuing token pairs.
type TokenIssuer interface {
	// IssueTokenPair generates a new access token and refresh token pair for a given user and client.
	//
	// Parameters:
	//	- ctx context.Context: The context for managing timeouts and cancellations.
	//	- userID string: The ID of the user for whom the token pair is being issued.
	//	- clientID string: The ID of the client requesting the tokens.
	//	- scopes types.Scope: The scopes to associate with the issued tokens.
	//	- nonce string: A value used to associate a client session with an ID token for replay protection.
	//	- claims *domain.ClaimsRequest: Optional custom claims to include in the tokens.
	//
	// Returns:
	//	- string: The issued access token.
	//	- string: The issued refresh token.
	//	- error: An error if token issuance fails.
	IssueTokenPair(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, claims *domain.ClaimsRequest) (string, string, error)

	// IssueIDToken creates an ID token for the specified user and client.
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
	IssueIDToken(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, authTime time.Time) (string, error)
}
