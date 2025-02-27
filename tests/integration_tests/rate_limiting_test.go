package integration_tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/security"
	"github.com/vigiloauth/vigilo/internal/users"
)

func setupRateLimitedServer(requestsPerMinute int, requestBody []byte) *httptest.ResponseRecorder {
	serverConfig := config.NewDefaultServerConfig()
	serverConfig.RequestsPerMinute = requestsPerMinute
	vigiloIdentityServer := server.NewVigiloIdentityServer(serverConfig)

	req := httptest.NewRequest(http.MethodPost, users.UserEndpoints.Login, bytes.NewBuffer(requestBody))
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)
	return rr
}

func TestRateLimiting(t *testing.T) {
	users.ResetInMemoryUserStore()
	user := users.NewUser("", users.TestConstants.Email, users.TestConstants.Password)
	requestBody, err := json.Marshal(user)

	userStore := users.GetInMemoryUserStore()
	hashedPassword, _ := security.HashPassword(user.Password)
	user.Password = hashedPassword
	_ = userStore.AddUser(user)

	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	requestsPerMinute := 5
	for range requestsPerMinute {
		rr := setupRateLimitedServer(requestsPerMinute, requestBody)
		if rr.Code != http.StatusOK {
			t.Fatalf("Expected status code 200, got %d", rr.Code)
		}
	}

	rr := setupRateLimitedServer(requestsPerMinute, requestBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status code 200, got %d", rr.Code)
	}
}
