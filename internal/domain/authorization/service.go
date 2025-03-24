package domain

// AuthorizationService defines the interface for handling client authorization requests.
type AuthorizationService interface {
	// AuthorizeClient handles the authorization logic for a client request.
	//
	// Parameters:
	//
	//   - userID: The ID of the user attempting to authorize the client.
	//   - clientID: The ID of the client requesting authorization.
	//   - redirectURI: The URI to redirect the user to after authorization.
	//   - scope: The requested authorization scopes.
	//   - state: An optional state parameter for maintaining request state between the client and the authorization server.
	//   - consentApproved: A boolean indicating whether the user has already approved consent for the requested scopes.
	//
	// Returns:
	//
	//   - bool: A boolean indicating whether authorization was successful.
	//   - string: The redirect URL, or an empty string if authorization failed.
	//   - string: An error message, or an empty string if authorization was successful.
	//
	// This method performs the following steps:
	//   1. Checks if the user is authenticated.
	//   2. Verifies user consent if required or if already approved.
	//   3. Generates an authorization code if authorization is successful.
	//   4. Constructs the redirect URL with the authorization code or error parameters.
	//   5. Returns the success status, redirect URL and any error messages.
	//
	// Errors:
	//
	//   - Returns an error message if the user is not authenticated, consent is denied, or authorization code generation fails.
	AuthorizeClient(userID, clientID, redirectURI, scope, state string, consentApproved bool) (string, error)
}
