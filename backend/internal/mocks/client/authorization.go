package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

var _ domain.ClientAuthorization = (*MockClientAuthorization)(nil)

type MockClientAuthorization struct {
	AuthorizeFunc func(ctx context.Context, request *domain.ClientAuthorizationRequest) (string, error)
}

func (m *MockClientAuthorization) Authorize(ctx context.Context, request *domain.ClientAuthorizationRequest) (string, error) {
	return m.AuthorizeFunc(ctx, request)
}
