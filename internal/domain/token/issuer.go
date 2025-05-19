package domain

import (
	"context"

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
}
