package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

var _ domain.AuthorizationCodeCreator = (*MockAuthorizationCodeCreator)(nil)

type MockAuthorizationCodeCreator struct {
	GenerateAuthorizationCodeFunc func(ctx context.Context, request *client.ClientAuthorizationRequest) (string, error)
}

func (m *MockAuthorizationCodeCreator) GenerateAuthorizationCode(ctx context.Context, request *client.ClientAuthorizationRequest) (string, error) {
	return m.GenerateAuthorizationCodeFunc(ctx, request)
}
