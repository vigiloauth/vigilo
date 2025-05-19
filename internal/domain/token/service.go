package domain

import (
	"context"
	"time"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

// TokenService defines the interface for managing JWT tokens.
type TokenService interface {
	// GenerateToken generates a refresh token for the given subject and expiration time.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - subject string: The subject of the token (e.g., user email).
	//   - audience string: The audience of the token (e.g., client ID).
	// 	 - scopes types.Scope: The scopes to be added to the token (can be an empty string if none are needed)..
	//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
	//   - nonce string: A random string used to prevent replay attacks provided by the client.
	//	 - tokenType types.TokenType: The type of token to create (BearerTokenType or AccessTokenType).
	//
	// Returns:
	//   - string: The generated JWT token string.
	//   - error: An error if token generation fails.
	GenerateToken(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string, tokenType types.TokenType) (string, error)

	GenerateAccessTokenWithClaims(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string, tokenType types.TokenType, claims *domain.ClaimsRequest) (string, error)

	// GenerateIDToken creates an ID token for the specified user and client.
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
	GenerateIDToken(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, authTime time.Time) (string, error)

	// ParseToken parses and validate the structure of a JWT token string.
	//
	// Parameters:
	//   - ctx ctx.Context: Context for the request, containing the request ID for logging.
	//   - tokenString string: The JWT token string to parse and validate.
	//
	// Returns:
	//   - *token.TokenClaims: The parsed token claims if successful.
	//   - error: An error if token parsing, decryption, or validation fails.
	ParseToken(ctx context.Context, tokenString string) (*TokenClaims, error)

	// GetTokenData retrieves the token data from the token repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to retrieve.
	//
	// Returns:
	//	- *TokenData: The TokenData if the token is valid, or nil if not found or invalid.
	//	- error: An error if the token is not found, expired, or the subject doesn't match.
	GetTokenData(ctx context.Context, token string) (*TokenData, error)

	// DeleteToken removes a token from the token repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to delete.
	//
	// Returns:
	//	- error: An error if the token deletion fails.
	DeleteToken(ctx context.Context, token string) error

	// ValidateToken checks to see if a token is blacklisted or expired.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token string to check.
	//
	// Returns:
	//	- error: An error if the token is blacklisted or expired.
	ValidateToken(ctx context.Context, token string) error

	// BlacklistToken adds the specified token to the blacklist, preventing it from being used
	// for further authentication or authorization. The token is marked as invalid, even if it
	// has not yet expired.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token to be blacklisted. This is the token that will no longer be valid for further use.
	//
	// Returns:
	//	- error: An error if the token is not found in the token store or if it has already expired, in which case it cannot be blacklisted.
	BlacklistToken(ctx context.Context, token string) error

	// DeleteExpiredTokens retrieves expired tokens from the repository and deletes them.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//
	// Returns:
	//	- error: An error if retrieval or deletion fails.
	DeleteExpiredTokens(ctx context.Context) error
}
