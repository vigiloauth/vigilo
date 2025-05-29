package domain

import "context"

type ClientAuthorization interface {
	// Authorize handles the authorization logic for a client request.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - authorizationRequest *ClientAuthorizationRequest: The client authorization request.
	//
	// Returns:
	//   - string: The redirect URL, or an empty string if authorization failed.
	//   - error: An error message, if any.
	//
	// Errors:
	//   - Returns an error message if the user is not authenticated, consent is denied, or authorization code generation fails.
	Authorize(ctx context.Context, request *ClientAuthorizationRequest) (string, error)
}
