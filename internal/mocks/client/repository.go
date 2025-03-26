package mocks

import client "github.com/vigiloauth/vigilo/internal/domain/client"

var _ client.ClientRepository = (*MockClientRepository)(nil)

// MockClientRepository is a mock implementation of the client.ClientStore interface.
type MockClientRepository struct {
	// SaveClientFunc is a mock function for the CreateClient method.
	SaveClientFunc func(client *client.Client) error

	// GetClientFunc is a mock function for the GetClient method.
	GetClientByIDFunc func(clientID string) *client.Client

	// DeleteClientFunc is a mock function for the DeleteClient method.
	DeleteClientByIDFunc func(clientID string) error

	// UpdateClientFunc is a mock function for the UpdateClient method.
	UpdateClientFunc func(client *client.Client) error

	IsExistingIDFunc func(clientID string) bool
}

// CreateClient calls the mock CreateClientFunc.
func (m *MockClientRepository) SaveClient(client *client.Client) error {
	return m.SaveClientFunc(client)
}

// GetClient calls the mock GetClientFunc.
func (m *MockClientRepository) GetClientByID(clientID string) *client.Client {
	return m.GetClientByIDFunc(clientID)
}

// DeleteClient calls the mock DeleteClientFunc.
func (m *MockClientRepository) DeleteClientByID(clientID string) error {
	return m.DeleteClientByIDFunc(clientID)
}

// UpdateClient calls the mock UpdateClientFunc.
func (m *MockClientRepository) UpdateClient(client *client.Client) error {
	return m.UpdateClientFunc(client)
}

func (m *MockClientRepository) IsExistingID(clientID string) bool {
	return m.IsExistingIDFunc(clientID)
}
