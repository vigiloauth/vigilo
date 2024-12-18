package integration_tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/users"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSEnforcement(t *testing.T) {
	tests := []struct {
		name           string
		useHTTPS       bool
		requestScheme  string
		expectedStatus int
	}{
		{
			name:           "HTTPS enforced - HTTP request should redirect",
			useHTTPS:       true,
			requestScheme:  "http",
			expectedStatus: http.StatusTemporaryRedirect,
		},
		{
			name:           "HTTPS enforced - HTTPS request should pass",
			useHTTPS:       true,
			requestScheme:  "https",
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "HTTPS not enforced - HTTP request should pass",
			useHTTPS:       false,
			requestScheme:  "http",
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "HTTPS not enforced - HTTPS request should pass",
			useHTTPS:       false,
			requestScheme:  "https",
			expectedStatus: http.StatusCreated,
		},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := createUniqueUserRegistrationRequest(i)
			serverInstance := server.NewVigiloIdentityServer(tt.useHTTPS)
			req := prepareRequest(tt.requestScheme, body)
			rec := httptest.NewRecorder()

			serverInstance.Router().ServeHTTP(rec, req)

			verifyStatusCode(t, rec.Code, tt.expectedStatus)
			if tt.expectedStatus == http.StatusTemporaryRedirect {
				verifyRedirectLocation(t, rec.Header().Get("Location"))
			}
		})
	}
}

func createUniqueUserRegistrationRequest(i int) []byte {
	username := fmt.Sprintf("%s_%d", users.TestConstants.Username, i)
	email := fmt.Sprintf("user%d@%s", i, users.TestConstants.Email[strings.Index(users.TestConstants.Email, "@")+1:])

	requestBody := users.NewUserRegistrationRequest(username, email, users.TestConstants.Password)
	body, _ := json.Marshal(requestBody)
	return body
}

func prepareRequest(requestScheme string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, users.UserEndpoints.Registration, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	if requestScheme == "https" {
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	return req
}

func verifyStatusCode(t *testing.T, actual, expected int) {
	if actual != expected {
		t.Errorf("Expected status %d, got %d", expected, actual)
	}
}

func verifyRedirectLocation(t *testing.T, location string) {
	if location == "" {
		t.Error("Expected redirect location header to be set")
	}
	if location[:5] != "https" {
		t.Errorf("Expected redirect to HTTPS, got %s", location)
	}
}
