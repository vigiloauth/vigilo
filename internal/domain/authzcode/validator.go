package domain

import (
	"context"

	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

type AuthorizationCodeValidator interface {
	// ValidateRequest checks the validity of the client authorization request.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - req *ClientAuthorizationRequest: The request to validate.
	//
	// Returns:
	//   - error: An error if the request is invalid.
	ValidateRequest(ctx context.Context, req *client.ClientAuthorizationRequest) error

	// ValidateAuthorizationCode checks if a code is valid and returns the associated data.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code to validate.
	//	- clientID string: The client requesting validation.
	//	- redirectURI string: The redirect URI to verify.
	//
	// Returns:
	//	- error: An error if validation fails.
	ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI string) error

	// ValidatePKCE validates the PKCE (Proof Key for Code Exchange) parameters during the token exchange process.
	//
	// This method checks if the provided code verifier matches the code challenge stored in the authorization code data.
	// It supports the "S256" (SHA-256) and "plain" code challenge methods.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- authzCodeData (*authz.AuthorizationCodeData): The authorization code data containing the code challenge and method.
	//	- codeVerifier (string): The code verifier provided by the client during the token exchange.
	//
	// Returns:
	//	- error: An error if the validation fails, including cases where the code verifier does not match the code challenge
	//	  or if the code challenge method is unsupported. Returns nil if validation succeeds.
	ValidatePKCE(ctx context.Context, authzCodeData *AuthorizationCodeData, codeVerifier string) error
}
