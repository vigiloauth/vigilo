package mocks

import (
	"context"
	"time"

	domain "github.com/vigiloauth/vigilo/internal/domain/audit"
)

var _ domain.AuditLogger = (*MockAuditLogger)(nil)

type MockAuditLogger struct {
	StoreEventFunc      func(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error)
	DeleteOldEventsFunc func(cts context.Context, olderThan time.Time) error
}

func (m *MockAuditLogger) StoreEvent(ctx context.Context, eventType domain.EventType, success bool, action domain.ActionType, method domain.MethodType, err error) {
	m.StoreEventFunc(ctx, eventType, success, action, method, err)
}

func (m *MockAuditLogger) DeleteOldEvents(ctx context.Context, olderThan time.Time) error {
	return m.DeleteOldEventsFunc(ctx, olderThan)
}
