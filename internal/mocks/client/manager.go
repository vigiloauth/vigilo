package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

var _ domain.ClientManager = (*MockClientManager)(nil)

type MockClientManager struct {
	RegenerateClientSecretFunc  func(ctx context.Context, clientID string) (*domain.ClientSecretRegenerationResponse, error)
	GetClientByIDFunc           func(ctx context.Context, clientID string) (*domain.Client, error)
	GetClientInformationFunc    func(ctx context.Context, clientID string, registrationAccessToken string) (*domain.ClientInformationResponse, error)
	UpdateClientInformationFunc func(ctx context.Context, clientID string, registrationAccessToken string, req *domain.ClientUpdateRequest) (*domain.ClientInformationResponse, error)
	DeleteClientInformationFunc func(ctx context.Context, clientID string, registrationAccessToken string) error
}

func (m *MockClientManager) RegenerateClientSecret(ctx context.Context, clientID string) (*domain.ClientSecretRegenerationResponse, error) {
	return m.RegenerateClientSecretFunc(ctx, clientID)
}

func (m *MockClientManager) GetClientByID(ctx context.Context, clientID string) (*domain.Client, error) {
	return m.GetClientByIDFunc(ctx, clientID)
}

func (m *MockClientManager) GetClientInformation(ctx context.Context, clientID string, registrationAccessToken string) (*domain.ClientInformationResponse, error) {
	return m.GetClientInformationFunc(ctx, clientID, registrationAccessToken)
}

func (m *MockClientManager) UpdateClientInformation(ctx context.Context, clientID string, registrationAccessToken string, req *domain.ClientUpdateRequest) (*domain.ClientInformationResponse, error) {
	return m.UpdateClientInformationFunc(ctx, clientID, registrationAccessToken, req)
}

func (m *MockClientManager) DeleteClientInformation(ctx context.Context, clientID string, registrationAccessToken string) error {
	return m.DeleteClientInformationFunc(ctx, clientID, registrationAccessToken)
}
