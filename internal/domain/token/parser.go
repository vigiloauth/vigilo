package domain

import "context"

type TokenParser interface {
	// ParseToken parses a JWT token string into TokenClaims.
	//
	// Parameters:
	//   - ctx ctx.Context: Context for the request, containing the request ID for logging.
	//   - tokenString string: The JWT token string to parse and validate.
	//
	// Returns:
	//   - *token.TokenClaims: The parsed token claims if successful.
	//   - error: An error if token parsing, decryption, or validation fails.
	ParseToken(ctx context.Context, tokenString string) (*TokenClaims, error)
}
