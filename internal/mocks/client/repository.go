package mocks

import (
	"context"

	client "github.com/vigiloauth/vigilo/internal/domain/client"
)

var _ client.ClientRepository = (*MockClientRepository)(nil)

type MockClientRepository struct {
	SaveClientFunc       func(ctx context.Context, client *client.Client) error
	GetClientByIDFunc    func(ctx context.Context, clientID string) (*client.Client, error)
	DeleteClientByIDFunc func(ctx context.Context, clientID string) error
	UpdateClientFunc     func(ctx context.Context, client *client.Client) error
	IsExistingIDFunc     func(ctx context.Context, clientID string) bool
}

func (m *MockClientRepository) SaveClient(ctx context.Context, client *client.Client) error {
	return m.SaveClientFunc(ctx, client)
}

func (m *MockClientRepository) GetClientByID(ctx context.Context, clientID string) (*client.Client, error) {
	return m.GetClientByIDFunc(ctx, clientID)
}

func (m *MockClientRepository) DeleteClientByID(ctx context.Context, clientID string) error {
	return m.DeleteClientByIDFunc(ctx, clientID)
}

func (m *MockClientRepository) UpdateClient(ctx context.Context, client *client.Client) error {
	return m.UpdateClientFunc(ctx, client)
}

func (m *MockClientRepository) IsExistingID(ctx context.Context, clientID string) bool {
	return m.IsExistingIDFunc(ctx, clientID)
}
