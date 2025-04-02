package domain

import (
	client "github.com/vigiloauth/vigilo/internal/domain/client"
)

type AuthorizationCodeService interface {
	// GenerateAuthorizationCode creates a new authorization code and stores it with associated data.
	//
	// Parameters:
	//
	//	 request *ClientAuthorizationRequest: The request containing the metadata to generate an authorization code.
	//
	// Returns:
	//
	//	 string: The generated authorization code.
	//   error: An error if code generation fails.
	GenerateAuthorizationCode(request *client.ClientAuthorizationRequest) (string, error)

	// ValidateAuthorizationCode checks if a code is valid and returns associated data.
	//
	// Parameters:
	//
	//   code string: The authorization code to validate.
	//   clientID string: The client requesting validation.
	//   redirectURI string: The redirect URI to verify.
	//
	// Returns:
	//
	//   *AuthorizationCodeData: The data associated with the code.
	//   error: An error if validation fails.
	ValidateAuthorizationCode(code, clientID, redirectURI string) (*AuthorizationCodeData, error)

	// RevokeAuthorizationCode explicitly invalidates a code.
	//
	// Parameters:
	//
	//   code string: The authorization code to revoke.
	//
	// Returns:
	//
	//   error: An error if revocation fails.
	RevokeAuthorizationCode(code string) error

	// GetAuthorizationCode retrieves the authorization code data for a given code.
	//
	// Parameters:
	//
	//	code string: The authorization code to retrieve.
	//
	// Returns:
	//
	//	*AuthorizationCodeData: The authorization code data if found, or nil if no matching code exists.
	GetAuthorizationCode(code string) (*AuthorizationCodeData, error)
}
