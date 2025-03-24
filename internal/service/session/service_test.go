package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	"github.com/vigiloauth/vigilo/internal/errors"
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

	mockTokenService.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) {
		return testToken, nil
	}

	mockSessionRepo.SaveSessionFunc = func(sessionData *session.SessionData) error {
		return nil
	}

	sessionService := NewSessionServiceImpl(mockTokenService, mockSessionRepo)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", nil)

	jwtConfig := config.NewJWTConfig()
	err := sessionService.CreateSession(w, r, testID, jwtConfig.ExpirationTime())
	assert.NoError(t, err)

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "session_token", cookie.Name)
	assert.NotEmpty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
}

func TestSessionService_InvalidateSession(t *testing.T) {
	config.NewServerConfig(config.WithForceHTTPS())
	mockTokenService := &mTokenService.MockTokenService{}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}

	config.NewJWTConfig()

	mockTokenService.GenerateTokenFunc = func(subject string, expirationTime time.Duration) (string, error) {
		return testToken, nil
	}

	mockTokenService.ParseTokenFunc = func(tokenString string) (*jwt.StandardClaims, error) {
		return &jwt.StandardClaims{Subject: testEmail}, nil
	}

	mockTokenService.IsTokenBlacklistedFunc = func(tokenString string) bool { return false }
	mockTokenService.SaveTokenFunc = func(tokenString, email string, expirationTime time.Time) {}
	mockTokenService.IsTokenBlacklistedFunc = func(tokenString string) bool { return tokenString == testToken }
	mockSessionRepo.DeleteSessionByIDFunc = func(sessionID string) error { return nil }

	sessionService := NewSessionServiceImpl(mockTokenService, mockSessionRepo)

	r := httptest.NewRequest("POST", "/invalidate", nil)
	r.Header.Set("Authorization", "Bearer "+testToken)

	w := httptest.NewRecorder()

	err := sessionService.InvalidateSession(w, r)
	assert.NoError(t, err)

	cookie := w.Result().Cookies()[0]
	assert.Equal(t, "session_token", cookie.Name)
	assert.Empty(t, cookie.Value)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)

	assert.True(t, mockTokenService.IsTokenBlacklistedFunc(testToken), "token should be blacklisted")
}

func TestSessionService_GetUserIDFromSession(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}

	t.Run("Success", func(t *testing.T) {
		ss := NewSessionServiceImpl(mockTokenService, mockSessionRepo)

		expectedUserID := "test-user-id"
		expectedToken := "valid-token"

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  sessionTokenName,
			Value: expectedToken,
		})

		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{Subject: expectedUserID}, nil
		}

		userID := ss.GetUserIDFromSession(req)

		assert.Equal(t, expectedUserID, userID)
	})

	t.Run("Session cookie not found in header", func(t *testing.T) {
		ss := NewSessionServiceImpl(mockTokenService, mockSessionRepo)

		req := httptest.NewRequest("GET", "/test", nil)

		userID := ss.GetUserIDFromSession(req)

		assert.Equal(t, "", userID)
	})

	t.Run("Error when failing to parse session token", func(t *testing.T) {
		ss := NewSessionServiceImpl(mockTokenService, mockSessionRepo)

		expectedToken := "invalid-token"

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  sessionTokenName,
			Value: expectedToken,
		})

		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
		}

		userID := ss.GetUserIDFromSession(req)

		assert.Equal(t, "", userID)
	})
}

func TestSessionService_UpdateSession(t *testing.T) {
	mockTokenService := &mTokenService.MockTokenService{}
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}

	t.Run("Sucess", func(t *testing.T) {
		mockSessionRepo.UpdateSessionByIDFunc = func(sessionID string, sessionData *session.SessionData) error {
			return nil
		}

		service := NewSessionServiceImpl(mockTokenService, mockSessionRepo)

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  sessionTokenName,
			Value: testSessionID,
		})

		err := service.UpdateSession(req, getTestSessionData())
		assert.NoError(t, err)
	})

	t.Run("Error is returned when database error occurs", func(t *testing.T) {
		mockSessionRepo.UpdateSessionByIDFunc = func(sessionID string, sessionData *session.SessionData) error {
			return errors.NewInternalServerError()
		}

		service := NewSessionServiceImpl(mockTokenService, mockSessionRepo)

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  sessionTokenName,
			Value: testSessionID,
		})

		err := service.UpdateSession(req, getTestSessionData())
		assert.Error(t, err)
	})
}

func TestSessionService_GetSessionData(t *testing.T) {
	mockSessionRepo := &mSessionRepo.MockSessionRepository{}
	sessionService := NewSessionServiceImpl(nil, mockSessionRepo)

	testSessionID := "test-session-id"
	testSessionData := &session.SessionData{
		ID:             testSessionID,
		UserID:         "test-user-id",
		ExpirationTime: time.Now().Add(1 * time.Minute),
	}

	t.Run("Success", func(t *testing.T) {
		mockSessionRepo.GetSessionByIDFunc = func(sessionID string) (*session.SessionData, error) {
			return testSessionData, nil
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  sessionTokenName,
			Value: testSessionID,
		})

		data, err := sessionService.GetSessionData(req)
		assert.NoError(t, err)
		assert.Equal(t, testSessionData, data)
	})

	t.Run("Session cookie not found", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		data, err := sessionService.GetSessionData(req)
		assert.Error(t, err)
		assert.Nil(t, data)
	})

	t.Run("Session not found in repository", func(t *testing.T) {
		mockSessionRepo.GetSessionByIDFunc = func(sessionID string) (*session.SessionData, error) {
			return nil, nil // Simulate session not found
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  "session_id",
			Value: testSessionID,
		})

		data, err := sessionService.GetSessionData(req)
		assert.Error(t, err)
		assert.Nil(t, data)
	})

	t.Run("Repository error", func(t *testing.T) {
		mockSessionRepo.GetSessionByIDFunc = func(sessionID string) (*session.SessionData, error) {
			return nil, errors.NewInternalServerError()
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.AddCookie(&http.Cookie{
			Name:  "session_id",
			Value: testSessionID,
		})

		data, err := sessionService.GetSessionData(req)
		assert.Error(t, err)
		assert.Nil(t, data)
	})
}

func getTestSessionData() *session.SessionData {
	return &session.SessionData{
		ID:             testSessionID,
		UserID:         testID,
		ExpirationTime: time.Now().Add(1 * time.Minute),
	}
}
