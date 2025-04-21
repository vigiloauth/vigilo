package mocks

import (
	"context"
	"time"

	domain "github.com/vigiloauth/vigilo/internal/domain/audit"
)

var _ domain.AuditRepository = (*MockAuditRepository)(nil)

type MockAuditRepository struct {
	StoreAuditEventFunc func(ctx context.Context, event *domain.AuditEvent) error
	GetAuditEventsFunc  func(ctx context.Context, filters map[string]any, from time.Time, to time.Time, limit, offset int) ([]*domain.AuditEvent, error)
	DeleteOldEventsFunc func(ctx context.Context, olderThan time.Time) error
}

func (m *MockAuditRepository) StoreAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	return m.StoreAuditEventFunc(ctx, event)
}

func (m *MockAuditRepository) GetAuditEvents(ctx context.Context, filters map[string]any, from time.Time, to time.Time, limit, offset int) ([]*domain.AuditEvent, error) {
	return m.GetAuditEventsFunc(ctx, filters, from, to, limit, offset)
}

func (m *MockAuditRepository) DeleteOldEvents(ctx context.Context, olderThan time.Time) error {
	return m.DeleteOldEventsFunc(ctx, olderThan)
}
