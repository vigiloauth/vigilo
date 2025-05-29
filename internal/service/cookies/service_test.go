package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
)

const (
	testSessionID string = "session-1234"
	testRequestID string = "req-1234"
)

func TestHTTPCookieService_SetSessionCookie(t *testing.T) {
	service := NewHTTPCookieService()
	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)
	expirationTime := 30 * time.Minute

	service.SetSessionCookie(ctx, w, testSessionID, expirationTime)
	response := w.Result()

	cookies := response.Cookies()
	assert.Len(t, cookies, 1, "Expected one cookie to be set")

	expectedCookieName := config.GetServerConfig().SessionCookieName()
	expectedDomain := config.GetServerConfig().Domain()

	if len(cookies) > 0 {
		cookie := cookies[0]
		assert.Equal(t, expectedCookieName, cookie.Name, "Cookie name should match server configuration")
		assert.Equal(t, testSessionID, cookie.Value, "Cookie value should be the session ID")
		assert.True(t, cookie.HttpOnly, "Cookie should be HttpOnly")
		assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite, "Cookie should use SameSite")
		assert.Equal(t, "/", cookie.Path, "Cookie path should be root")
		assert.Equal(t, expectedDomain, cookie.Domain, "Cookie domain should match server configuration")
	}
}

func TestHTTPCookieService_ClearSessionCookie(t *testing.T) {
	service := NewHTTPCookieService()
	w := httptest.NewRecorder()
	ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

	service.ClearSessionCookie(ctx, w)
	response := w.Result()

	cookies := response.Cookies()
	assert.Len(t, cookies, 1, "Expected one cookie to be set")

	expectedCookieName := config.GetServerConfig().SessionCookieName()
	expectedDomain := config.GetServerConfig().Domain()

	if len(cookies) > 0 {
		cookie := cookies[0]
		assert.Equal(t, expectedCookieName, cookie.Name, "Cookie name should match configuration")
		assert.Empty(t, cookie.Value, "Cookie value should be empty")
		assert.True(t, cookie.HttpOnly, "Cookie should be HttpOnly")
		assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite, "Cookie should use SameSite=Strict")
		assert.Equal(t, expectedDomain, cookie.Domain, "Cookie domain should match configuration")

		assert.True(t, cookie.Expires.Before(time.Now()), "Cookie should already be expired")
	}
}

func TestHTTPCookieService_GetSessionCookie(t *testing.T) {
	service := NewHTTPCookieService()
	testURL := "http://example.com"

	req := httptest.NewRequest(http.MethodGet, testURL, nil)
	req.AddCookie(&http.Cookie{
		Name:  config.GetServerConfig().SessionCookieName(),
		Value: testSessionID,
	})

	cookie, err := service.GetSessionCookie(req)
	require.NoError(t, err, "Should not return an error when cookie exists")
	assert.NotNil(t, cookie, "Should return a cookie")
	assert.Equal(t, testSessionID, cookie.Value, "Cookie value should what was set")

	reqWithoutCookie := httptest.NewRequest(http.MethodGet, testURL, nil)

	cookie, err = service.GetSessionCookie(reqWithoutCookie)
	require.Error(t, err, "Should return an error when cookie doesn't exist")
	assert.Nil(t, cookie, "Should not return a cookie when it doesn't exist")
}
