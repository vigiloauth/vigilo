package mocks

import (
	"context"
	"net/http"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/session"
)

var _ domain.SessionManager = (*MockSessionManager)(nil)

type MockSessionManager struct {
	GetUserIDFromSessionFunc      func(ctx context.Context, r *http.Request) (string, error)
	GetUserAuthenticationTimeFunc func(ctx context.Context, r *http.Request) (int64, error)
}

func (m *MockSessionManager) GetUserIDFromSession(ctx context.Context, r *http.Request) (string, error) {
	return m.GetUserIDFromSessionFunc(ctx, r)
}

func (m *MockSessionManager) GetUserAuthenticationTime(ctx context.Context, r *http.Request) (int64, error) {
	return m.GetUserAuthenticationTimeFunc(ctx, r)
}
