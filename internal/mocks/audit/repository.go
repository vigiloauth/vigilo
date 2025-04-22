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
	DeleteEventFunc     func(ctx context.Context, eventID string) error
}

func (m *MockAuditRepository) StoreAuditEvent(ctx context.Context, event *domain.AuditEvent) error {
	return m.StoreAuditEventFunc(ctx, event)
}

func (m *MockAuditRepository) GetAuditEvents(ctx context.Context, filters map[string]any, from time.Time, to time.Time, limit, offset int) ([]*domain.AuditEvent, error) {
	return m.GetAuditEventsFunc(ctx, filters, from, to, limit, offset)
}

func (m *MockAuditRepository) DeleteEvent(ctx context.Context, eventID string) error {
	return m.DeleteEventFunc(ctx, eventID)
}
