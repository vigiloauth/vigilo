package mocks

import (
	"time"

	session "github.com/vigiloauth/vigilo/internal/domain/session"
)

var _ session.SessionRepository = (*MockSessionRepository)(nil)

type MockSessionRepository struct {
	SaveSessionFunc            func(sessionData *session.SessionData) error
	GetSessionByIDFunc         func(sessionID string) (*session.SessionData, error)
	UpdateSessionByIDFunc      func(sessionID string, sessionData *session.SessionData) error
	DeleteSessionByIDFunc      func(sessionID string) error
	CleanupExpiredSessionsFunc func(ticker *time.Ticker)
}

func (m *MockSessionRepository) SaveSession(sessionData *session.SessionData) error {
	return m.SaveSessionFunc(sessionData)
}

func (m *MockSessionRepository) GetSessionByID(sessionID string) (*session.SessionData, error) {
	return m.GetSessionByIDFunc(sessionID)
}

func (m *MockSessionRepository) UpdateSessionByID(sessionID string, sessionData *session.SessionData) error {
	return m.UpdateSessionByIDFunc(sessionID, sessionData)
}

func (m *MockSessionRepository) DeleteSessionByID(sessionID string) error {
	return m.DeleteSessionByIDFunc(sessionID)
}

func (m *MockSessionRepository) CleanupExpiredSessions(ticker *time.Ticker) {
	m.CleanupExpiredSessionsFunc(ticker)
}
