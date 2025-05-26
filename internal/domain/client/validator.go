package domain

import (
	"context"
)

type ClientValidator interface {
	ValidateRegistrationRequest(ctx context.Context, req *ClientRegistrationRequest) error
	ValidateUpdateRequest(ctx context.Context, req *ClientUpdateRequest) error
	ValidateAuthorizationRequest(ctx context.Context, req *ClientAuthorizationRequest) error
	ValidateRedirectURI(ctx context.Context, redirectURI string, existingClient *Client) error
	ValidateClientAndRegistrationAccessToken(ctx context.Context, clientID string, registrationAccessToken string) error
}
