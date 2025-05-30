package mocks

import (
	"context"
	"net/http"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ domain.ClientAuthenticator = (*MockClientAuthenticator)(nil)

type MockClientAuthenticator struct {
	AuthenticateRequestFunc func(ctx context.Context, r *http.Request, requiredScope types.Scope) error
	AuthenticateClientFunc  func(ctx context.Context, req *domain.ClientAuthenticationRequest) error
}

func (m *MockClientAuthenticator) AuthenticateRequest(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
	return m.AuthenticateRequestFunc(ctx, r, requiredScope)
}

func (m *MockClientAuthenticator) AuthenticateClient(ctx context.Context, req *domain.ClientAuthenticationRequest) error {
	return m.AuthenticateClientFunc(ctx, req)
}
