package mocks

import "github.com/vigiloauth/vigilo/internal/client"

type MockClientStore struct {
	CreateClientFunc func(client *client.Client) error
	GetClientFunc    func(clientID string) *client.Client
	DeleteClientFunc func(clientID string) error
	UpdateClientFunc func(client *client.Client) error
}

func (m *MockClientStore) CreateClient(client *client.Client) error {
	return m.CreateClientFunc(client)
}

func (m *MockClientStore) GetClient(clientID string) *client.Client {
	return m.GetClientFunc(clientID)
}

func (m *MockClientStore) DeleteClient(clientID string) error {
	return m.DeleteClientFunc(clientID)
}

func (m *MockClientStore) UpdateClient(client *client.Client) error {
	return m.UpdateClientFunc(client)
}
