package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

var _ domain.ClientValidator = (*MockClientValidator)(nil)

type MockClientValidator struct {
	ValidateRegistrationRequestFunc              func(ctx context.Context, req *domain.ClientRegistrationRequest) error
	ValidateUpdateRequestFunc                    func(ctx context.Context, req *domain.ClientUpdateRequest) error
	ValidateAuthorizationRequestFunc             func(ctx context.Context, req *domain.ClientAuthorizationRequest) error
	ValidateRedirectURIFunc                      func(ctx context.Context, redirectURI string, existingClient *domain.Client) error
	ValidateClientAndRegistrationAccessTokenFunc func(ctx context.Context, clientID string, registrationAccessToken string) error
}

func (m *MockClientValidator) ValidateRegistrationRequest(ctx context.Context, req *domain.ClientRegistrationRequest) error {
	return m.ValidateRegistrationRequestFunc(ctx, req)
}

func (m *MockClientValidator) ValidateUpdateRequest(ctx context.Context, req *domain.ClientUpdateRequest) error {
	return m.ValidateUpdateRequestFunc(ctx, req)
}

func (m *MockClientValidator) ValidateAuthorizationRequest(ctx context.Context, req *domain.ClientAuthorizationRequest) error {
	return m.ValidateAuthorizationRequestFunc(ctx, req)
}

func (m *MockClientValidator) ValidateRedirectURI(ctx context.Context, redirectURI string, existingClient *domain.Client) error {
	return m.ValidateRedirectURIFunc(ctx, redirectURI, existingClient)
}

func (m *MockClientValidator) ValidateClientAndRegistrationAccessToken(ctx context.Context, clientID string, registrationAccessToken string) error {
	return m.ValidateClientAndRegistrationAccessTokenFunc(ctx, clientID, registrationAccessToken)
}
