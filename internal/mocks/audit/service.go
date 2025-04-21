package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/internal/domain/audit"
)

var _ domain.AuditLogger = (*MockAuditLogger)(nil)

type MockAuditLogger struct {
	StoreEventFunc func(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error)
}

func (m *MockAuditLogger) StoreEvent(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
	m.StoreEventFunc(ctx, eventType, success, action, method, err)
}
