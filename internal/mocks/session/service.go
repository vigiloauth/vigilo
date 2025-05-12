package mocks

import (
	"net/http"

	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
)

var _ session.SessionService = (*MockSessionService)(nil)

type MockSessionService struct {
	CreateSessionFunc        func(w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) error
	InvalidateSessionFunc    func(w http.ResponseWriter, r *http.Request) error
	GetUserIDFromSessionFunc func(r *http.Request) (string, error)
	UpdateSessionFunc        func(r *http.Request, sessionData *session.SessionData) error
	GetSessionDataFunc       func(r *http.Request) (*session.SessionData, error)
}

func (m *MockSessionService) CreateSession(w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) error {
	return m.CreateSessionFunc(w, r, sessionData)
}

func (m *MockSessionService) InvalidateSession(w http.ResponseWriter, r *http.Request) error {
	return m.InvalidateSessionFunc(w, r)
}

func (m *MockSessionService) GetUserIDFromSession(r *http.Request) (string, error) {
	return m.GetUserIDFromSessionFunc(r)
}

func (m *MockSessionService) UpdateSession(r *http.Request, sessionData *session.SessionData) error {
	return m.UpdateSessionFunc(r, sessionData)
}

func (m *MockSessionService) GetSessionData(r *http.Request) (*session.SessionData, error) {
	return m.GetSessionDataFunc(r)
}
