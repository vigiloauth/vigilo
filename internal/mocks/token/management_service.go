package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

var _ domain.TokenManagementService = (*MockTokenManagementService)(nil)

type MockTokenManagementService struct {
	IntrospectFunc func(ctx context.Context, tokenStr string) *domain.TokenIntrospectionResponse
	RevokeFunc     func(ctx context.Context, tokenStr string) error
}

func (m *MockTokenManagementService) Introspect(ctx context.Context, tokenStr string) *domain.TokenIntrospectionResponse {
	return m.IntrospectFunc(ctx, tokenStr)
}

func (m *MockTokenManagementService) Revoke(ctx context.Context, tokenStr string) error {
	return m.RevokeFunc(ctx, tokenStr)
}
