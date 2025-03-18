package mocks

import "github.com/vigiloauth/vigilo/internal/client"

// MockEmailService is a mock implementation of the client.ClientService interface.
type MockClientStore struct {
	// SaveClientFunc is a mock function for the CreateClient method.
	SaveClientFunc func(client *client.Client) error

	// GetClientFunc is a mock function for the GetClient method.
	GetClientByIDFunc func(clientID string) *client.Client

	// DeleteClientFunc is a mock function for the DeleteClient method.
	DeleteClientByIDFunc func(clientID string) error

	// UpdateClientFunc is a mock function for the UpdateClient method.
	UpdateClientFunc func(client *client.Client) error
}

// CreateClient calls the mock CreateClientFunc.
func (m *MockClientStore) SaveClient(client *client.Client) error {
	return m.SaveClientFunc(client)
}

// GetClient calls the mock GetClientFunc.
func (m *MockClientStore) GetClientByID(clientID string) *client.Client {
	return m.GetClientByIDFunc(clientID)
}

// DeleteClient calls the mock DeleteClientFunc.
func (m *MockClientStore) DeleteClientByID(clientID string) error {
	return m.DeleteClientByIDFunc(clientID)
}

// UpdateClient calls the mock UpdateClientFunc.
func (m *MockClientStore) UpdateClient(client *client.Client) error {
	return m.UpdateClientFunc(client)
}
