package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mAuditLogger "github.com/vigiloauth/vigilo/v2/internal/mocks/audit"
	mCookieService "github.com/vigiloauth/vigilo/v2/internal/mocks/cookies"
	mSessionRepo "github.com/vigiloauth/vigilo/v2/internal/mocks/session"
)

const (
	testEmail     string = "test@example.com"
	testUserID    string = "user-1234"
	testSessionID string = "sess-1234"
	testURL       string = "http://test.com"
)

func TestSessionService_CreateSession(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		sessionRepo := &mSessionRepo.MockSessionRepository{
			SaveSessionFunc: func(ctx context.Context, sessionData *session.SessionData) error {
				return nil
			},
		}
		cookieService := &mCookieService.MockHTTPCookieService{
			SetSessionCookieFunc: func(ctx context.Context, w http.ResponseWriter, token string, expirationTime time.Duration) {},
		}
		auditLogger := &mAuditLogger.MockAuditLogger{
			StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {
			},
		}

		service := NewSessionService(sessionRepo, cookieService, auditLogger)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		err := service.CreateSession(w, r, getTestSessionData())
		require.NoError(t, err, "Expected no error when creating a session")
	})

	t.Run("Error is returned saving the session", func(t *testing.T) {
		sessionRepo := &mSessionRepo.MockSessionRepository{
			SaveSessionFunc: func(ctx context.Context, sessionData *session.SessionData) error {
				return errors.New(errors.ErrCodeDuplicateSession, "session already exists with the given ID")
			},
		}
		auditLogger := &mAuditLogger.MockAuditLogger{
			StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {
			},
		}

		service := NewSessionService(sessionRepo, nil, auditLogger)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		err := service.CreateSession(w, r, getTestSessionData())
		require.Error(t, err, "Expected an error when creating a session")
	})
}

func TestSessionService_InvalidateSession(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		sessionRepo := &mSessionRepo.MockSessionRepository{
			DeleteSessionByIDFunc: func(ctx context.Context, sessionID string) error {
				return nil
			},
		}
		auditLogger := &mAuditLogger.MockAuditLogger{
			StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {
			},
		}
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return &http.Cookie{Value: testSessionID}, nil
			},
			ClearSessionCookieFunc: func(ctx context.Context, w http.ResponseWriter) {},
		}

		service := NewSessionService(sessionRepo, cookieService, auditLogger)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		err := service.InvalidateSession(w, r)
		require.NoError(t, err, "Expected no error when invalidating session")
	})

	t.Run("Error is returned retrieving session cookie", func(t *testing.T) {
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return nil, errors.New(errors.ErrCodeMissingHeader, "session cookie not found in header")
			},
		}

		service := NewSessionService(nil, cookieService, nil)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		err := service.InvalidateSession(w, r)
		require.Error(t, err, "Expected an error when retrieving session cookie")
	})

	t.Run("Error is returned deleting session by ID", func(t *testing.T) {
		sessionRepo := &mSessionRepo.MockSessionRepository{
			DeleteSessionByIDFunc: func(ctx context.Context, sessionID string) error {
				return errors.New(errors.ErrCodeSessionNotFound, "session not found with the given ID")
			},
		}
		auditLogger := &mAuditLogger.MockAuditLogger{
			StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {
			},
		}
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return &http.Cookie{Value: testSessionID}, nil
			},
		}

		service := NewSessionService(sessionRepo, cookieService, auditLogger)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		err := service.InvalidateSession(w, r)
		require.Error(t, err, "Expected an error when retrieving the session by ID")
	})
}

func TestSessionService_GetUserIDFromSession(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		sessionRepo := &mSessionRepo.MockSessionRepository{
			GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*session.SessionData, error) {
				return getTestSessionData(), nil
			},
		}
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return &http.Cookie{Value: testSessionID}, nil
			},
		}

		service := NewSessionService(sessionRepo, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		userID, err := service.GetUserIDFromSession(r)
		require.NoError(t, err, "Expected no error when invalidating session")
		assert.Equal(t, testUserID, userID, "Expected user ID's to match")
	})

	t.Run("Error is returned retrieving session cookie", func(t *testing.T) {
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return nil, errors.New(errors.ErrCodeMissingHeader, "session cookie not found in header")
			},
		}

		service := NewSessionService(nil, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		userID, err := service.GetUserIDFromSession(r)
		require.Error(t, err, "Expected an error retrieving session cookie")
		assert.Empty(t, userID, "Expected user ID to be empty")
	})

	t.Run("Error is returned retrieving session data by ID", func(t *testing.T) {
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return &http.Cookie{Value: testSessionID}, nil
			},
		}
		sessionRepo := &mSessionRepo.MockSessionRepository{
			GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*session.SessionData, error) {
				return nil, errors.New(errors.ErrCodeSessionNotFound, "session not found with the given ID")
			},
		}

		service := NewSessionService(sessionRepo, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		userID, err := service.GetUserIDFromSession(r)
		require.Error(t, err, "Expected an error retrieving session data")
		assert.Empty(t, userID, "Expected user ID to be empty")
	})
}

func TestSessionService_UpdateSession(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		sessionRepo := &mSessionRepo.MockSessionRepository{
			UpdateSessionByIDFunc: func(ctx context.Context, sessionID string, sessionData *session.SessionData) error {
				return nil
			},
		}
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return &http.Cookie{Value: testSessionID}, nil
			},
		}

		service := NewSessionService(sessionRepo, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		err := service.UpdateSession(r, getTestSessionData())
		require.NoError(t, err, "Expected no error when updating session")
	})

	t.Run("Error is returned retrieving session cookie", func(t *testing.T) {
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return nil, errors.New(errors.ErrCodeMissingHeader, "session cookie not found in header")
			},
		}

		service := NewSessionService(nil, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		err := service.UpdateSession(r, getTestSessionData())
		require.Error(t, err, "Expected an error when retrieving session cookie")
	})

	t.Run("Error is returned when cookie value and sessionID do not match", func(t *testing.T) {
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return &http.Cookie{Value: "invalid ID"}, nil
			},
		}

		service := NewSessionService(nil, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		err := service.UpdateSession(r, getTestSessionData())
		require.Error(t, err, "Expected an error when updating session")
	})

	t.Run("Error is returned updating session", func(t *testing.T) {
		sessionRepo := &mSessionRepo.MockSessionRepository{
			UpdateSessionByIDFunc: func(ctx context.Context, sessionID string, sessionData *session.SessionData) error {
				return errors.New(errors.ErrCodeSessionNotFound, "session not found with the given ID")
			},
		}
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return &http.Cookie{Value: testSessionID}, nil
			},
		}

		service := NewSessionService(sessionRepo, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		err := service.UpdateSession(r, getTestSessionData())
		require.Error(t, err, "Expected an error when updating session by ID")
	})
}

func TestSessionService_GetSessionData(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		sessionRepo := &mSessionRepo.MockSessionRepository{
			GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*session.SessionData, error) {
				return getTestSessionData(), nil
			},
		}
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return &http.Cookie{Value: testSessionID}, nil
			},
		}

		service := NewSessionService(sessionRepo, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		sessionData, err := service.GetSessionData(r)
		require.NoError(t, err, "Expected no error when retrieving session by ID")
		assert.NotNil(t, sessionData, "Expected session data to not be nil")
	})

	t.Run("Error is returned retrieving session cookie", func(t *testing.T) {
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return nil, errors.New(errors.ErrCodeMissingHeader, "session cookie not found in header")
			},
		}

		service := NewSessionService(nil, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		sessionData, err := service.GetSessionData(r)
		require.Error(t, err, "Expected an error when retrieving session cookie")
		assert.Nil(t, sessionData, "Expected session data to be nil")
	})

	t.Run("Error is returned retrieving session by ID", func(t *testing.T) {
		sessionRepo := &mSessionRepo.MockSessionRepository{
			GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*session.SessionData, error) {
				return nil, errors.New(errors.ErrCodeSessionNotFound, "session not found by ID")
			},
		}
		cookieService := &mCookieService.MockHTTPCookieService{
			GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
				return &http.Cookie{Value: testSessionID}, nil
			},
		}

		service := NewSessionService(sessionRepo, cookieService, nil)
		r := httptest.NewRequest(http.MethodGet, testURL, nil)

		sessionData, err := service.GetSessionData(r)
		require.Error(t, err, "Expected an error when retrieving session by ID")
		assert.Nil(t, sessionData, "Expected session data to be nil")
	})
}

func getTestSessionData() *session.SessionData {
	return &session.SessionData{
		ID:             testSessionID,
		UserID:         testUserID,
		ExpirationTime: time.Now().Add(1 * time.Minute),
	}
}
