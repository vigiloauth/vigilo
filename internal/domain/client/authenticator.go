package domain

import (
	"context"
	"net/http"

	"github.com/vigiloauth/vigilo/v2/internal/types"
)

// ClientRequestAuthenticator defines an interface for authenticating HTTP client requests.
type ClientRequestAuthenticator interface {
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
}
