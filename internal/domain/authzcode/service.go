package domain

import "time"

type AuthorizationCodeService interface {
	// GenerateAuthorizationCode creates a new authorization code and stores it with associated data.
	//
	// Parameters:
	//
	//   userID string: The user who authorized the client.
	//   clientID string: The client requesting authorization.
	//   redirectURI string: The URI to redirect after authorization.
	//   scope string: The authorized scope(s).
	//
	// Returns:
	//
	//   string: The generated authorization code.
	//   error: An error if code generation fails.
	GenerateAuthorizationCode(userID, clientID, redirectURI, scope string) (string, error)

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

	// SetAuthorizationCodeLifeTime configures how long authorization codes remain valid.
	//
	// Parameters:
	//
	//   lifetime time.Duration: The validity period for new codes.
	SetAuthorizationCodeLifeTime(lifetime time.Duration)
}
