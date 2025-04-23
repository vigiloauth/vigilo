package domain

import (
	"context"

	client "github.com/vigiloauth/vigilo/internal/domain/client"
)

type AuthorizationCodeService interface {
	// GenerateAuthorizationCode creates a new authorization code and stores it with associated data.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- request *ClientAuthorizationRequest: The request containing the metadata to generate an authorization code.
	//
	// Returns:
	//	- string: The generated authorization code.
	//	- error: An error if code generation fails.
	GenerateAuthorizationCode(ctx context.Context, request *client.ClientAuthorizationRequest) (string, error)

	// ValidateAuthorizationCode checks if a code is valid and returns the associated data.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code to validate.
	//	- clientID string: The client requesting validation.
	//	- redirectURI string: The redirect URI to verify.
	//
	// Returns:
	//	- *AuthorizationCodeData: The data associated with the code.
	//	- error: An error if validation fails.
	ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI string) (*AuthorizationCodeData, error)

	// RevokeAuthorizationCode explicitly invalidates a code.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code to revoke.
	//
	// Returns:
	//	- error: An error if revocation fails.
	RevokeAuthorizationCode(ctx context.Context, code string) error

	// GetAuthorizationCode retrieves the authorization code data for a given code.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- code string: The authorization code to retrieve.
	//
	// Returns:
	//	- *AuthorizationCodeData: The authorization code data if found, or nil if no matching code exists.
	GetAuthorizationCode(ctx context.Context, code string) (*AuthorizationCodeData, error)

	// ValidatePKCE validates the PKCE (Proof Key for Code Exchange) parameters during the token exchange process.
	//
	// This method checks if the provided code verifier matches the code challenge stored in the authorization code data.
	// It supports the "S256" (SHA-256) and "plain" code challenge methods.
	//
	// Parameters:
	//	- authzCodeData (*authz.AuthorizationCodeData): The authorization code data containing the code challenge and method.
	//	- codeVerifier (string): The code verifier provided by the client during the token exchange.
	//
	// Returns:
	//	- error: An error if the validation fails, including cases where the code verifier does not match the code challenge
	//	  or if the code challenge method is unsupported. Returns nil if validation succeeds.
	ValidatePKCE(authzCodeData *AuthorizationCodeData, codeVerifier string) error

	// SaveAuthorizationCode stores the provided authorization code data in the repository.
	//
	// This method calculates the expiration time for the authorization code based on the
	// configured code lifetime and stores the code along with its associated data in the
	// authorization code repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- authData (*authz.AuthorizationCodeData): The authorization code data to be stored.
	//
	// Returns:
	//	- error: An error if storing the authorization code fails, or nil if the operation succeeds.
	SaveAuthorizationCode(ctx context.Context, authData *AuthorizationCodeData) error
}
