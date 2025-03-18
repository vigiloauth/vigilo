package mocks

import "github.com/vigiloauth/vigilo/internal/client"

// MockEmailService is a mock implementation of the client.ClientService interface.
type MockClientStore struct {
	// CreateClientFunc is a mock function for the CreateClient method.
	CreateClientFunc func(client *client.Client) error

	// GetClientFunc is a mock function for the GetClient method.
	GetClientFunc func(clientID string) *client.Client

	// DeleteClientFunc is a mock function for the DeleteClient method.
	DeleteClientFunc func(clientID string) error

	// UpdateClientFunc is a mock function for the UpdateClient method.
	UpdateClientFunc func(client *client.Client) error
}

// CreateClient calls the mock CreateClientFunc.
func (m *MockClientStore) CreateClient(client *client.Client) error {
	return m.CreateClientFunc(client)
}

// GetClient calls the mock GetClientFunc.
func (m *MockClientStore) GetClient(clientID string) *client.Client {
	return m.GetClientFunc(clientID)
}

// DeleteClient calls the mock DeleteClientFunc.
func (m *MockClientStore) DeleteClient(clientID string) error {
	return m.DeleteClientFunc(clientID)
}

// UpdateClient calls the mock UpdateClientFunc.
func (m *MockClientStore) UpdateClient(client *client.Client) error {
	return m.UpdateClientFunc(client)
}
