package mocks

import (
	"context"
	"net/http"
	"time"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/cookies"
)

var _ domain.HTTPCookieService = (*MockHTTPCookieService)(nil)

type MockHTTPCookieService struct {
	SetSessionCookieFunc   func(ctx context.Context, w http.ResponseWriter, token string, expirationTime time.Duration)
	ClearSessionCookieFunc func(ctx context.Context, w http.ResponseWriter)
	GetSessionCookieFunc   func(r *http.Request) (*http.Cookie, error)
}

func (m *MockHTTPCookieService) SetSessionCookie(ctx context.Context, w http.ResponseWriter, token string, expirationTime time.Duration) {
	m.SetSessionCookieFunc(ctx, w, token, expirationTime)
}

func (m *MockHTTPCookieService) ClearSessionCookie(ctx context.Context, w http.ResponseWriter) {
	m.ClearSessionCookieFunc(ctx, w)
}

func (m *MockHTTPCookieService) GetSessionCookie(r *http.Request) (*http.Cookie, error) {
	return m.GetSessionCookieFunc(r)
}
