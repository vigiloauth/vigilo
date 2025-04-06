package service

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	"github.com/vigiloauth/vigilo/internal/errors"
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
	mockTokenService := &mTokenService.MockTokenService{}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}
	mockCookieService := &mCookieService.MockHTTPCookieService{}

	mockTokenService.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) {
		return testToken, nil
	}
	mockSessionRepo.SaveSessionFunc = func(sessionData *session.SessionData) error {
		return nil
	}
	mockCookieService.SetSessionCookieFunc = func(w http.ResponseWriter, token string, expirationTime time.Duration) {}

	sessionService := NewSessionServiceImpl(mockTokenService, mockSessionRepo, mockCookieService)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	jwtConfig := config.NewTokenConfig()
	err := sessionService.CreateSession(w, r, testID, jwtConfig.ExpirationTime())
	assert.NoError(t, err)
}

func TestSessionService_InvalidateSession(t *testing.T) {
	config.NewServerConfig(config.WithForceHTTPS())
	config.NewTokenConfig()
	mockTokenService := &mTokenService.MockTokenService{}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}
	mockCookieService := &mCookieService.MockHTTPCookieService{}

	mockTokenService.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) {
		return testToken, nil
	}
	mockTokenService.ParseTokenFunc = func(tokenString string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: testEmail}, nil
	}
	mockCookieService.ClearSessionCookieFunc = func(w http.ResponseWriter) {}

	mockTokenService.IsTokenBlacklistedFunc = func(tokenString string) bool { return false }
	mockTokenService.SaveTokenFunc = func(tokenString, email string, expirationTime time.Time) {}
	mockTokenService.IsTokenBlacklistedFunc = func(tokenString string) bool { return tokenString == testToken }
	mockSessionRepo.DeleteSessionByIDFunc = func(sessionID string) error { return nil }

	sessionService := NewSessionServiceImpl(mockTokenService, mockSessionRepo, mockCookieService)

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

		ss := NewSessionServiceImpl(mockTokenService, mockSessionRepo, mockCookieService)

		expectedUserID := "test-user-id"
		expectedToken := "valid-token"

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  common.SessionToken,
			Value: expectedToken,
		})

		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{Subject: expectedUserID}, nil
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

		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
		}

		ss := NewSessionServiceImpl(mockTokenService, mockSessionRepo, mockCookieService)
		userID := ss.GetUserIDFromSession(req)
		assert.Equal(t, "", userID)
	})
}

func TestSessionService_UpdateSession(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}
	mockCookieService := &mCookieService.MockHTTPCookieService{}

	t.Run("Sucess", func(t *testing.T) {
		mockCookieService.GetSessionTokenFunc = func(r *http.Request) (string, error) {
			return testSessionID, nil
		}

		mockSessionRepo.UpdateSessionByIDFunc = func(sessionID string, sessionData *session.SessionData) error {
			return nil
		}

		service := NewSessionServiceImpl(mockTokenService, mockSessionRepo, mockCookieService)

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
		mockSessionRepo.UpdateSessionByIDFunc = func(sessionID string, sessionData *session.SessionData) error {
			return errors.NewInternalServerError()
		}

		service := NewSessionServiceImpl(mockTokenService, mockSessionRepo, mockCookieService)

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
	sessionService := NewSessionServiceImpl(nil, mockSessionRepo, mockCookieService)

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
		mockSessionRepo.GetSessionByIDFunc = func(sessionID string) (*session.SessionData, error) {
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
		mockSessionRepo.GetSessionByIDFunc = func(sessionID string) (*session.SessionData, error) {
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
		mockSessionRepo.GetSessionByIDFunc = func(sessionID string) (*session.SessionData, error) {
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
	t.Run("Success", func(t *testing.T) {
		mockSessionRepo := &mSessionRepo.MockSessionRepository{
			UpdateSessionByIDFunc: func(sessionID string, sessionData *session.SessionData) error {
				return nil
			},
		}

		session := getTestSessionData()
		session.State = "testState"
		service := NewSessionServiceImpl(nil, mockSessionRepo, nil)

		err := service.ClearStateFromSession(session)
		assert.NoError(t, err)
	})

	t.Run("Error is returned when updating the session", func(t *testing.T) {
		mockSessionRepo := &mSessionRepo.MockSessionRepository{
			UpdateSessionByIDFunc: func(sessionID string, sessionData *session.SessionData) error {
				return errors.NewInternalServerError()
			},
		}

		session := getTestSessionData()
		session.State = "testState"
		service := NewSessionServiceImpl(nil, mockSessionRepo, nil)

		err := service.ClearStateFromSession(session)
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
			GetSessionByIDFunc: func(sessionID string) (*session.SessionData, error) {
				return getTestSessionData(), nil
			},
		}

		req := &http.Request{
			URL: &url.URL{
				RawQuery: "state=testState",
			},
		}

		session := NewSessionServiceImpl(nil, mockSessionRepo, mockCookieService)
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
			GetSessionByIDFunc: func(sessionID string) (*session.SessionData, error) {
				return nil, errors.NewInternalServerError()
			},
		}

		req := httptest.NewRequest("GET", "/test&state=testState", nil)

		session := NewSessionServiceImpl(nil, mockSessionRepo, mockCookieService)
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
			GetSessionByIDFunc: func(sessionID string) (*session.SessionData, error) {
				return getTestSessionData(), nil
			},
		}

		req := httptest.NewRequest("GET", "/test&state=testState", nil)

		session := NewSessionServiceImpl(nil, mockSessionRepo, mockCookieService)
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
