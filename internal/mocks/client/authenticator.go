package mocks

import (
	"context"
	"net/http"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ domain.ClientRequestAuthenticator = (*MockClientAuthenticator)(nil)

type MockClientAuthenticator struct {
	AuthenticateRequestFunc func(ctx context.Context, r *http.Request, requiredScope types.Scope) error
}

func (m *MockClientAuthenticator) AuthenticateRequest(ctx context.Context, r *http.Request, requiredScope types.Scope) error {
	return m.AuthenticateRequestFunc(ctx, r, requiredScope)
}
