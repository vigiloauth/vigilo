package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/common"
	audit "github.com/vigiloauth/vigilo/internal/domain/audit"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	domain "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	mAuditLogger "github.com/vigiloauth/vigilo/internal/mocks/audit"
	mCookieService "github.com/vigiloauth/vigilo/internal/mocks/cookies"
	mSessionRepo "github.com/vigiloauth/vigilo/internal/mocks/session"
	mTokenService "github.com/vigiloauth/vigilo/internal/mocks/token"
)

const (
	testEmail     string = "test@example.com"
	testID        string = "id"
	testToken     string = "test_token"
	testSessionID string = "test_id"
)

func TestSessionService_CreateSession(t *testing.T) {
	config.NewServerConfig(config.WithForceHTTPS())
	mockTokenService := &mTokenService.MockTokenService{
		GenerateTokenFunc: func(ctx context.Context, id, scopes string, duration time.Duration) (string, error) {
			return testToken, nil
		},
	}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{
		SaveSessionFunc: func(ctx context.Context, sessionData *session.SessionData) error {
			return nil
		},
	}
	mockCookieService := &mCookieService.MockHTTPCookieService{
		SetSessionCookieFunc: func(ctx context.Context, w http.ResponseWriter, token string, expirationTime time.Duration) {},
	}
	mockAuditLogger := &mAuditLogger.MockAuditLogger{
		StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {
		},
	}

	sessionService := NewSessionService(mockTokenService, mockSessionRepo, mockCookieService, mockAuditLogger)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	jwtConfig := config.NewTokenConfig()
	err := sessionService.CreateSession(w, r, testID, jwtConfig.ExpirationTime())
	assert.NoError(t, err)
}

func TestSessionService_InvalidateSession(t *testing.T) {
	config.NewServerConfig(config.WithForceHTTPS())
	config.NewTokenConfig()
	mockTokenService := &mTokenService.MockTokenService{
		GenerateTokenFunc: func(ctx context.Context, subject, scopes string, expirationTime time.Duration) (string, error) {
			return testToken, nil
		},
		IsTokenBlacklistedFunc: func(ctx context.Context, tokenString string) (bool, error) {
			return false, nil
		},
		SaveTokenFunc: func(ctx context.Context, tokenString, email string, expirationTime time.Time) error {
			return nil
		},
		ParseTokenFunc: func(token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject: testEmail,
				},
			}, nil
		},
	}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{
		DeleteSessionByIDFunc: func(ctx context.Context, sessionID string) error {
			return nil
		},
	}
	mockCookieService := &mCookieService.MockHTTPCookieService{
		ClearSessionCookieFunc: func(ctx context.Context, w http.ResponseWriter) {},
	}
	mockAuditLogger := &mAuditLogger.MockAuditLogger{
		StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {
		},
	}

	sessionService := NewSessionService(mockTokenService, mockSessionRepo, mockCookieService, mockAuditLogger)

	r := httptest.NewRequest("POST", "/invalidate", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)

	w := httptest.NewRecorder()

	err := sessionService.InvalidateSession(w, r)
	assert.NoError(t, err)
}

func TestSessionService_GetUserIDFromSession(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}
	mockCookieService := &mCookieService.MockHTTPCookieService{}

	t.Run("Success", func(t *testing.T) {
		mockCookieService.GetSessionTokenFunc = func(r *http.Request) (string, error) {
			return testToken, nil
		}

		ss := NewSessionService(mockTokenService, mockSessionRepo, mockCookieService, nil)

		expectedUserID := "test-user-id"
		expectedToken := "valid-token"

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  common.SessionToken,
			Value: expectedToken,
		})

		mockTokenService.ParseTokenFunc = func(token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject: expectedUserID,
				},
			}, nil
		}

		userID := ss.GetUserIDFromSession(req)

		assert.Equal(t, expectedUserID, userID)
	})

	t.Run("Error when failing to parse session token", func(t *testing.T) {
		expectedToken := "invalid-token"
		mockCookieService.GetSessionTokenFunc = func(r *http.Request) (string, error) {
			return expectedToken, nil
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  common.SessionToken,
			Value: expectedToken,
		})

		mockTokenService.ParseTokenFunc = func(token string) (*domain.TokenClaims, error) {
			return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
		}

		ss := NewSessionService(mockTokenService, mockSessionRepo, mockCookieService, nil)
		userID := ss.GetUserIDFromSession(req)
		assert.Equal(t, "", userID)
	})
}

func TestSessionService_UpdateSession(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}
	mockCookieService := &mCookieService.MockHTTPCookieService{}

	t.Run("Success", func(t *testing.T) {
		mockCookieService.GetSessionTokenFunc = func(r *http.Request) (string, error) {
			return testSessionID, nil
		}

		mockSessionRepo.UpdateSessionByIDFunc = func(ctx context.Context, sessionID string, sessionData *session.SessionData) error {
			return nil
		}

		service := NewSessionService(mockTokenService, mockSessionRepo, mockCookieService, nil)

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  testToken,
			Value: testSessionID,
		})

		err := service.UpdateSession(req, getTestSessionData())
		assert.NoError(t, err)
	})

	t.Run("Error is returned when database error occurs", func(t *testing.T) {
		mockCookieService.GetSessionTokenFunc = func(r *http.Request) (string, error) {
			return testSessionID, nil
		}
		mockSessionRepo.UpdateSessionByIDFunc = func(ctx context.Context, sessionID string, sessionData *session.SessionData) error {
			return errors.NewInternalServerError()
		}

		service := NewSessionService(mockTokenService, mockSessionRepo, mockCookieService, nil)

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  common.SessionToken,
			Value: testSessionID,
		})

		err := service.UpdateSession(req, getTestSessionData())
		assert.Error(t, err)
	})
}

func TestSessionService_GetSessionData(t *testing.T) {
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}
	mockCookieService := &mCookieService.MockHTTPCookieService{}
	sessionService := NewSessionService(nil, mockSessionRepo, mockCookieService, nil)

	testSessionID := "test-session-id"
	testSessionData := &session.SessionData{
		ID:             testSessionID,
		UserID:         "test-user-id",
		ExpirationTime: time.Now().Add(1 * time.Minute),
	}

	t.Run("Success", func(t *testing.T) {
		mockCookieService.GetSessionTokenFunc = func(r *http.Request) (string, error) {
			return testSessionID, nil
		}
		mockSessionRepo.GetSessionByIDFunc = func(ctx context.Context, sessionID string) (*session.SessionData, error) {
			return testSessionData, nil
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  common.SessionToken,
			Value: testSessionID,
		})

		data, err := sessionService.GetSessionData(req)
		assert.NoError(t, err)
		assert.Equal(t, testSessionData, data)
	})

	t.Run("Session cookie not found", func(t *testing.T) {
		mockCookieService.GetSessionTokenFunc = func(r *http.Request) (string, error) {
			return "", errors.NewInternalServerError()
		}
		req := httptest.NewRequest("GET", "/test", nil)

		data, err := sessionService.GetSessionData(req)
		assert.Error(t, err)
		assert.Nil(t, data)
	})

	t.Run("Session not found in repository", func(t *testing.T) {
		mockCookieService.GetSessionTokenFunc = func(r *http.Request) (string, error) {
			return testSessionID, nil
		}
		mockSessionRepo.GetSessionByIDFunc = func(ctx context.Context, sessionID string) (*session.SessionData, error) {
			return nil, errors.NewInternalServerError() // Simulate session not found
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  common.SessionToken,
			Value: testSessionID,
		})

		data, err := sessionService.GetSessionData(req)
		assert.Error(t, err)
		assert.Nil(t, data)
	})

	t.Run("Repository error", func(t *testing.T) {
		mockCookieService.GetSessionTokenFunc = func(r *http.Request) (string, error) {
			return testSessionID, nil
		}
		mockSessionRepo.GetSessionByIDFunc = func(ctx context.Context, sessionID string) (*session.SessionData, error) {
			return nil, errors.NewInternalServerError()
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  common.SessionToken,
			Value: testSessionID,
		})

		data, err := sessionService.GetSessionData(req)
		assert.Error(t, err)
		assert.Nil(t, data)
	})
}

func TestSessionService_ClearStateFromSession(t *testing.T) {
	ctx := context.Background()
	t.Run("Success", func(t *testing.T) {
		mockSessionRepo := &mSessionRepo.MockSessionRepository{
			UpdateSessionByIDFunc: func(ctx context.Context, sessionID string, sessionData *session.SessionData) error {
				return nil
			},
		}

		session := getTestSessionData()
		session.State = "testState"
		service := NewSessionService(nil, mockSessionRepo, nil, nil)

		err := service.ClearStateFromSession(ctx, session)
		assert.NoError(t, err)
	})

	t.Run("Error is returned when updating the session", func(t *testing.T) {
		mockSessionRepo := &mSessionRepo.MockSessionRepository{
			UpdateSessionByIDFunc: func(ctx context.Context, sessionID string, sessionData *session.SessionData) error {
				return errors.NewInternalServerError()
			},
		}

		session := getTestSessionData()
		session.State = "testState"
		service := NewSessionService(nil, mockSessionRepo, nil, nil)

		err := service.ClearStateFromSession(ctx, session)
		assert.Error(t, err)
	})
}

func TestSessionService_ValidateSessionState(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCookieService := &mCookieService.MockHTTPCookieService{
			GetSessionTokenFunc: func(r *http.Request) (string, error) {
				return testSessionID, nil
			},
		}
		mockSessionRepo := &mSessionRepo.MockSessionRepository{
			GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*session.SessionData, error) {
				return getTestSessionData(), nil
			},
		}

		req := &http.Request{
			URL: &url.URL{
				RawQuery: "state=testState",
			},
		}

		session := NewSessionService(nil, mockSessionRepo, mockCookieService, nil)
		result, err := session.ValidateSessionState(req)

		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("Error is returning retrieving session data", func(t *testing.T) {
		mockCookieService := &mCookieService.MockHTTPCookieService{
			GetSessionTokenFunc: func(r *http.Request) (string, error) {
				return testSessionID, nil
			},
		}
		mockSessionRepo := &mSessionRepo.MockSessionRepository{
			GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*session.SessionData, error) {
				return nil, errors.NewInternalServerError()
			},
		}

		req := httptest.NewRequest("GET", "/test&state=testState", nil)

		session := NewSessionService(nil, mockSessionRepo, mockCookieService, nil)
		result, err := session.ValidateSessionState(req)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("Error is returned when there is a state mismatch", func(t *testing.T) {
		mockCookieService := &mCookieService.MockHTTPCookieService{
			GetSessionTokenFunc: func(r *http.Request) (string, error) {
				return testSessionID, nil
			},
		}
		mockSessionRepo := &mSessionRepo.MockSessionRepository{
			GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*session.SessionData, error) {
				return getTestSessionData(), nil
			},
		}

		req := httptest.NewRequest("GET", "/test&state=testState", nil)

		session := NewSessionService(nil, mockSessionRepo, mockCookieService, nil)
		result, err := session.ValidateSessionState(req)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, "state parameter does not match with session state", err.Error())
	})
}

func getTestSessionData() *session.SessionData {
	return &session.SessionData{
		ID:             testSessionID,
		UserID:         testID,
		ExpirationTime: time.Now().Add(1 * time.Minute),
		State:          "testState",
	}
}
