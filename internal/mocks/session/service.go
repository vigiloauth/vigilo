package mocks

import (
	"context"
	"net/http"

	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
)

var _ session.SessionService = (*MockSessionService)(nil)

type MockSessionService struct {
	GetOrCreateSessionFunc   func(ctx context.Context, w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) (*session.SessionData, error)
	InvalidateSessionFunc    func(w http.ResponseWriter, r *http.Request) error
	GetUserIDFromSessionFunc func(r *http.Request) string
	UpdateSessionFunc        func(r *http.Request, sessionData *session.SessionData) error
	GetSessionDataFunc       func(r *http.Request) (*session.SessionData, error)
	IsUserSessionPresentFunc func(r *http.Request, userID string) bool
}

func (m *MockSessionService) GetOrCreateSession(ctx context.Context, w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) (*session.SessionData, error) {
	return m.GetOrCreateSessionFunc(ctx, w, r, sessionData)
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

func (m *MockSessionService) IsUserSessionPresent(r *http.Request, userID string) bool {
	return m.IsUserSessionPresentFunc(r, userID)
}
