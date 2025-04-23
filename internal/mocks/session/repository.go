package mocks

import (
	"context"

	session "github.com/vigiloauth/vigilo/internal/domain/session"
)

var _ session.SessionRepository = (*MockSessionRepository)(nil)

type MockSessionRepository struct {
	SaveSessionFunc       func(ctx context.Context, sessionData *session.SessionData) error
	GetSessionByIDFunc    func(ctx context.Context, sessionID string) (*session.SessionData, error)
	UpdateSessionByIDFunc func(ctx context.Context, sessionID string, sessionData *session.SessionData) error
	DeleteSessionByIDFunc func(ctx context.Context, sessionID string) error
}

func (m *MockSessionRepository) SaveSession(ctx context.Context, sessionData *session.SessionData) error {
	return m.SaveSessionFunc(ctx, sessionData)
}

func (m *MockSessionRepository) GetSessionByID(ctx context.Context, sessionID string) (*session.SessionData, error) {
	return m.GetSessionByIDFunc(ctx, sessionID)
}

func (m *MockSessionRepository) UpdateSessionByID(ctx context.Context, sessionID string, sessionData *session.SessionData) error {
	return m.UpdateSessionByIDFunc(ctx, sessionID, sessionData)
}

func (m *MockSessionRepository) DeleteSessionByID(ctx context.Context, sessionID string) error {
	return m.DeleteSessionByIDFunc(ctx, sessionID)
}
