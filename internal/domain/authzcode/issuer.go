package domain

import (
	"context"

	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

type AuthorizationCodeIssuer interface {
	// IssueAuthorizationCode generates an authorization code for the given client request.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - req *ClientAuthorizationRequest: The request containing the metadata to generate an authorization code.
	//
	// Returns:
	//   - string: The generated authorization code.
	//   - error: An error if code generation fails.
	IssueAuthorizationCode(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error)
}
