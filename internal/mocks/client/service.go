package mocks

import client "github.com/vigiloauth/vigilo/internal/domain/client"

var _ client.ClientService = (*MockClientService)(nil)

type MockClientService struct {
	RegisterFunc                  func(newClient *client.Client) (*client.ClientRegistrationResponse, error)
	RegenerateClientSecretFunc    func(clientID string) (*client.ClientSecretRegenerationResponse, error)
	GetClientByIDFunc             func(clientID string) *client.Client
	ValidateClientRedirectURIFunc func(redirectURI string, existingClient *client.Client) error
	ValidateAndRetrieveClientFunc func(clientID, registrationAccessToken string) (*client.ClientInformationResponse, error)
	ValidateAndUpdateClientFunc   func(clientID, registrationAccessToken string, request *client.ClientUpdateRequest) (*client.ClientInformationResponse, error)
	ValidateAndDeleteClientFunc   func(clientID, registrationAccessToken string) error
	AuthenticateClientFunc        func(clientID string, clientSecret string, grantType string, scopes string) error
}

func (m *MockClientService) Register(newClient *client.Client) (*client.ClientRegistrationResponse, error) {
	return m.RegisterFunc(newClient)
}

func (m *MockClientService) RegenerateClientSecret(clientID string) (*client.ClientSecretRegenerationResponse, error) {
	return m.RegenerateClientSecretFunc(clientID)
}

func (m *MockClientService) GetClientByID(clientID string) *client.Client {
	return m.GetClientByIDFunc(clientID)
}

func (m *MockClientService) ValidateClientRedirectURI(redirectURI string, existingClient *client.Client) error {
	return m.ValidateClientRedirectURIFunc(redirectURI, existingClient)
}

func (m *MockClientService) ValidateAndRetrieveClient(clientID, registrationAccessToken string) (*client.ClientInformationResponse, error) {
	return m.ValidateAndRetrieveClientFunc(clientID, registrationAccessToken)
}

func (m *MockClientService) ValidateAndUpdateClient(clientID, registrationAccessToken string, request *client.ClientUpdateRequest) (*client.ClientInformationResponse, error) {
	return m.ValidateAndUpdateClientFunc(clientID, registrationAccessToken, request)
}

func (m *MockClientService) ValidateAndDeleteClient(clientID, registrationAccessToken string) error {
	return m.ValidateAndDeleteClientFunc(clientID, registrationAccessToken)
}

func (m *MockClientService) AuthenticateClient(clientID string, clientSecret string, grantType string, scopes string) error {
	return m.AuthenticateClientFunc(clientID, clientSecret, grantType, scopes)
}
