package mocks

import client "github.com/vigiloauth/vigilo/internal/domain/client"

type MockClientService struct {
	RegisterFunc                              func(newClient *client.Client) (*client.ClientRegistrationResponse, error)
	RegenerateClientSecretFunc                func(clientID string) (*client.ClientSecretRegenerationResponse, error)
	AuthenticateClientForCredentialsGrantFunc func(clientID, clientSecret string) (*client.Client, error)
	GetClientByIDFunc                         func(clientID string) *client.Client
	ValidateClientRedirectURIFunc             func(redirectURI string, existingClient *client.Client) error
}

func (m *MockClientService) Register(newClient *client.Client) (*client.ClientRegistrationResponse, error) {
	return m.RegisterFunc(newClient)
}

func (m *MockClientService) RegenerateClientSecret(clientID string) (*client.ClientSecretRegenerationResponse, error) {
	return m.RegenerateClientSecretFunc(clientID)
}

func (m *MockClientService) AuthenticateClientForCredentialsGrant(clientID, clientSecret string) (*client.Client, error) {
	return m.AuthenticateClientForCredentialsGrantFunc(clientID, clientSecret)
}

func (m *MockClientService) GetClientByID(clientID string) *client.Client {
	return m.GetClientByIDFunc(clientID)
}

func (m *MockClientService) ValidateClientRedirectURI(redirectURI string, existingClient *client.Client) error {
	return m.ValidateClientRedirectURIFunc(redirectURI, existingClient)
}
