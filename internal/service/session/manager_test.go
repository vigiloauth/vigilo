package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mockCookies "github.com/vigiloauth/vigilo/v2/internal/mocks/cookies"
	sessionMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/session"
)

func TestSessionManager_GetUserAuthenticationTime(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		request     *http.Request
		repo        *sessionMocks.MockSessionRepository
		cookies     *mockCookies.MockHTTPCookieService
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			request:     httptest.NewRequest(http.MethodGet, "/", nil),
			repo: &sessionMocks.MockSessionRepository{
				GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*domain.SessionData, error) {
					return &domain.SessionData{
						UserID:             "user123",
						AuthenticationTime: time.Now().Unix(), // Example timestamp
					}, nil
				},
			},
			cookies: &mockCookies.MockHTTPCookieService{
				GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
					return &http.Cookie{
						Name:  "session_id",
						Value: "valid_session_id",
					}, nil
				},
			},
		},
		{
			name:        "Missing header error is returned",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeMissingHeader],
			request:     httptest.NewRequest(http.MethodGet, "/", nil),
			cookies: &mockCookies.MockHTTPCookieService{
				GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
					return nil, errors.New(errors.ErrCodeMissingHeader, "session cookie not found in header")
				},
			},
		},
		{
			name:        "Session not found error is returned",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeSessionNotFound],
			request:     httptest.NewRequest(http.MethodGet, "/", nil),
			repo: &sessionMocks.MockSessionRepository{
				GetSessionByIDFunc: func(ctx context.Context, sessionID string) (*domain.SessionData, error) {
					return nil, errors.New(errors.ErrCodeSessionNotFound, "session not found")
				},
			},
			cookies: &mockCookies.MockHTTPCookieService{
				GetSessionCookieFunc: func(r *http.Request) (*http.Cookie, error) {
					return &http.Cookie{
						Name:  "session_id",
						Value: "valid_session_id",
					}, nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			sut := NewSessionManager(test.repo, test.cookies)

			authTime, err := sut.GetUserAuthenticationTime(ctx, test.request)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error message does not match")
				assert.Equal(t, int64(0), authTime, "Expected authentication time to be zero on error")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.Greater(t, authTime, int64(0), "Expected authentication time to be greater than zero")
			}
		})
	}
}
