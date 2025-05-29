package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

var _ domain.ClientCreator = (*MockClientCreator)(nil)

type MockClientCreator struct {
	RegisterFunc func(ctx context.Context, client *domain.ClientRegistrationRequest) (*domain.ClientRegistrationResponse, error)
}

func (m *MockClientCreator) Register(ctx context.Context, client *domain.ClientRegistrationRequest) (*domain.ClientRegistrationResponse, error) {
	return m.RegisterFunc(ctx, client)
}
