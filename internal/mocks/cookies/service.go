package mocks

import (
	"net/http"
	"time"
)

type MockHTTPCookieService struct {
	SetSessionCookieFunc   func(w http.ResponseWriter, token string, expirationTime time.Duration)
	ClearSessionCookieFunc func(w http.ResponseWriter)
	GetSessionTokenFunc    func(r *http.Request) (string, error)
}

func (m *MockHTTPCookieService) SetSessionCookie(w http.ResponseWriter, token string, expirationTime time.Duration) {
	m.SetSessionCookieFunc(w, token, expirationTime)
}

func (m *MockHTTPCookieService) ClearSessionCookie(w http.ResponseWriter) {
	m.ClearSessionCookieFunc(w)
}

func (m *MockHTTPCookieService) GetSessionToken(r *http.Request) (string, error) {
	return m.GetSessionTokenFunc(r)
}
