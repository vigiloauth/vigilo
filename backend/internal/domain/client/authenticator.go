package domain

import (
	"context"
	"net/http"

	"github.com/vigiloauth/vigilo/v2/internal/types"
)

// ClientAuthenticator defines an interface for authenticating HTTP client requests.
type ClientAuthenticator interface {
	// AuthenticateRequest validates the incoming HTTP request to ensure the client has the required scope.
	//
	// Parameters:
	//	- ctx context.Context: The context for managing timeouts and cancellations.
	//	- r *http.Request: The HTTP request to authenticate.
	//	- requiredScope types.Scope: The scope required to access the requested resource.
	//
	// Returns:
	//	- error: An error if authentication fails or the required scope is not met.
	AuthenticateRequest(ctx context.Context, r *http.Request, requiredScope types.Scope) error

	// AuthenticateClient authenticates the client using provided credentials
	// and authorizes access by validating required grant types and scopes.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- req *ClientAuthenticationRequest: The request containing client credentials and required scopes.
	//
	// Returns:
	//	- error: An error if authentication or authorization fails.
	AuthenticateClient(ctx context.Context, req *ClientAuthenticationRequest) error
}
