package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mAuditLogger "github.com/vigiloauth/vigilo/v2/internal/mocks/audit"
	mCookieService "github.com/vigiloauth/vigilo/v2/internal/mocks/cookies"
	mSessionRepo "github.com/vigiloauth/vigilo/v2/internal/mocks/session"
	mTokenService "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
)

const (
	testEmail     string = "test@example.com"
	testID        string = "id"
	testToken     string = "test_token"
	testSessionID string = "test_id"
)

func TestSessionService_GetOrCreateSession(t *testing.T) {
	tests := []struct {
		name          string
		wantErr       bool
		tokenService  *mTokenService.MockTokenService
		cookieService *mCookieService.MockHTTPCookieService
		sessionRepo   *mSessionRepo.MockSessionRepository
	}{
		{
			name:    "Success when retrieving existing session",
			wantErr: false,
			cookieService: &mCookieService.MockHTTPCookieService{
				GetSessionTokenFunc: func(r *http.Request) (string, error) {
					return testToken, nil
				},
			},
			tokenService: &mTokenService.MockTokenService{
				DecryptTokenFunc: func(ctx context.Context, encryptedToken string) (string, error) {
					return testToken, nil
				},
			},
			sessionRepo: &mSessionRepo.MockSessionRepository{
				GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*session.SessionData, error) {
					return getTestSessionData(), nil
				},
			},
		},
		{
			name:    "Error retrieving session token should create a new session",
			wantErr: false,
			cookieService: &mCookieService.MockHTTPCookieService{
				GetSessionTokenFunc: func(r *http.Request) (string, error) {
					return "", errors.New(errors.ErrCodeMissingHeader, "session token not found")
				},
				SetSessionCookieFunc: func(ctx context.Context, w http.ResponseWriter, token string, expirationTime time.Duration) {},
			},
			sessionRepo: &mSessionRepo.MockSessionRepository{
				SaveSessionFunc: func(ctx context.Context, sessionData *session.SessionData) error {
					return nil
				},
			},
			tokenService: &mTokenService.MockTokenService{
				EncryptTokenFunc: func(ctx context.Context, signedToken string) (string, error) {
					return testToken, nil
				},
			},
		},
		{
			name:    "Error decrypting token should not create new session",
			wantErr: true,
			cookieService: &mCookieService.MockHTTPCookieService{
				GetSessionTokenFunc: func(r *http.Request) (string, error) {
					return testToken, nil
				},
			},
			tokenService: &mTokenService.MockTokenService{
				DecryptTokenFunc: func(ctx context.Context, encryptedToken string) (string, error) {
					return "", errors.New(errors.ErrCodeTokenDecryption, "failed to decrypt token")
				},
			},
			sessionRepo: nil,
		},
		{
			name:    "DB error should return an error",
			wantErr: true,
			cookieService: &mCookieService.MockHTTPCookieService{
				GetSessionTokenFunc: func(r *http.Request) (string, error) {
					return testToken, nil
				},
			},
			tokenService: &mTokenService.MockTokenService{
				DecryptTokenFunc: func(ctx context.Context, encryptedToken string) (string, error) {
					return testToken, nil
				},
			},
			sessionRepo: &mSessionRepo.MockSessionRepository{
				GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*session.SessionData, error) {
					return nil, errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			ctx := context.WithValue(req.Context(), constants.ContextKeyRequestID, "test_request_id")

			service := NewSessionService(test.tokenService, test.sessionRepo, test.cookieService, nil)
			session, err := service.GetOrCreateSession(ctx, w, req, getTestSessionData())

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, session, "Expected the session to be nil but got: %v", session)
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, session, "Expected the session to not be nil")
			}
		})
	}
}

func TestSessionService_InvalidateSession(t *testing.T) {
	config.NewServerConfig(config.WithForceHTTPS())
	config.NewTokenConfig()
	mockTokenService := &mTokenService.MockTokenService{
		GenerateTokenFunc: func(ctx context.Context, subject, scopes, roles string, expirationTime time.Duration) (string, error) {
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
			Name:  constants.SessionTokenHeader,
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
			Name:  constants.SessionTokenHeader,
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
			Name:  constants.SessionTokenHeader,
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
			Name:  constants.SessionTokenHeader,
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
			Name:  constants.SessionTokenHeader,
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
			Name:  constants.SessionTokenHeader,
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
		ClientID:       "client-ID",
		ExpirationTime: time.Now().Add(1 * time.Minute),
		ClientName:     "client-name",
	}
}
