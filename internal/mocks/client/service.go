package mocks

import (
	"context"

	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ client.ClientService = (*MockClientService)(nil)

type MockClientService struct {
	RegisterFunc                  func(ctx context.Context, newClient *client.Client) (*client.ClientRegistrationResponse, error)
	RegenerateClientSecretFunc    func(ctx context.Context, clientID string) (*client.ClientSecretRegenerationResponse, error)
	GetClientByIDFunc             func(ctx context.Context, clientID string) (*client.Client, error)
	ValidateClientRedirectURIFunc func(redirectURI string, existingClient *client.Client) error
	ValidateAndRetrieveClientFunc func(ctx context.Context, clientID, registrationAccessToken string) (*client.ClientInformationResponse, error)
	ValidateAndUpdateClientFunc   func(ctx context.Context, clientID, registrationAccessToken string, request *client.ClientUpdateRequest) (*client.ClientInformationResponse, error)
	ValidateAndDeleteClientFunc   func(ctx context.Context, clientID, registrationAccessToken string) error
	AuthenticateClientFunc        func(ctx context.Context, clientID string, clientSecret string, grantType string, scopes types.Scope) error
}

func (m *MockClientService) Register(ctx context.Context, newClient *client.Client) (*client.ClientRegistrationResponse, error) {
	return m.RegisterFunc(ctx, newClient)
}

func (m *MockClientService) RegenerateClientSecret(ctx context.Context, clientID string) (*client.ClientSecretRegenerationResponse, error) {
	return m.RegenerateClientSecretFunc(ctx, clientID)
}

func (m *MockClientService) GetClientByID(ctx context.Context, clientID string) (*client.Client, error) {
	return m.GetClientByIDFunc(ctx, clientID)
}

func (m *MockClientService) ValidateClientRedirectURI(redirectURI string, existingClient *client.Client) error {
	return m.ValidateClientRedirectURIFunc(redirectURI, existingClient)
}

func (m *MockClientService) ValidateAndRetrieveClient(ctx context.Context, clientID, registrationAccessToken string) (*client.ClientInformationResponse, error) {
	return m.ValidateAndRetrieveClientFunc(ctx, clientID, registrationAccessToken)
}

func (m *MockClientService) ValidateAndUpdateClient(ctx context.Context, clientID, registrationAccessToken string, request *client.ClientUpdateRequest) (*client.ClientInformationResponse, error) {
	return m.ValidateAndUpdateClientFunc(ctx, clientID, registrationAccessToken, request)
}

func (m *MockClientService) ValidateAndDeleteClient(ctx context.Context, clientID, registrationAccessToken string) error {
	return m.ValidateAndDeleteClientFunc(ctx, clientID, registrationAccessToken)
}

func (m *MockClientService) AuthenticateClient(ctx context.Context, clientID string, clientSecret string, grantType string, scopes types.Scope) error {
	return m.AuthenticateClientFunc(ctx, clientID, clientSecret, grantType, scopes)
}
