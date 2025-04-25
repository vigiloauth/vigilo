package mocks

import (
	"context"
	"net/http"
	"time"

	session "github.com/vigiloauth/vigilo/internal/domain/session"
)

var _ session.SessionService = (*MockSessionService)(nil)

type MockSessionService struct {
	CreateSessionFunc         func(w http.ResponseWriter, r *http.Request, userID string, sessionExpiration time.Duration) error
	InvalidateSessionFunc     func(w http.ResponseWriter, r *http.Request) error
	GetUserIDFromSessionFunc  func(r *http.Request) string
	UpdateSessionFunc         func(r *http.Request, sessionData *session.SessionData) error
	GetSessionDataFunc        func(r *http.Request) (*session.SessionData, error)
	ClearStateFromSessionFunc func(ctx context.Context, sessionData *session.SessionData) error
	ValidateSessionStateFunc  func(r *http.Request) (*session.SessionData, error)
	IsUserSessionPresentFunc  func(r *http.Request, userID string) bool
}

func (m *MockSessionService) CreateSession(w http.ResponseWriter, r *http.Request, userID string, sessionExpiration time.Duration) error {
	return m.CreateSessionFunc(w, r, userID, sessionExpiration)
}

func (m *MockSessionService) InvalidateSession(w http.ResponseWriter, r *http.Request) error {
	return m.InvalidateSessionFunc(w, r)
}

func (m *MockSessionService) GetUserIDFromSession(r *http.Request) string {
	return m.GetUserIDFromSessionFunc(r)
}

func (m *MockSessionService) UpdateSession(r *http.Request, sessionData *session.SessionData) error {
	return m.UpdateSessionFunc(r, sessionData)
}

func (m *MockSessionService) GetSessionData(r *http.Request) (*session.SessionData, error) {
	return m.GetSessionDataFunc(r)
}

func (m *MockSessionService) ClearStateFromSession(ctx context.Context, sessionData *session.SessionData) error {
	return m.ClearStateFromSessionFunc(ctx, sessionData)
}

func (m *MockSessionService) ValidateSessionState(r *http.Request) (*session.SessionData, error) {
	return m.ValidateSessionStateFunc(r)
}

func (m *MockSessionService) IsUserSessionPresent(r *http.Request, userID string) bool {
	return m.IsUserSessionPresentFunc(r, userID)
}
