package integration_tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func setupRateLimitedServer(requestsPerMinute int, requestBody []byte) *httptest.ResponseRecorder {
	config.NewServerConfig(config.WithMaxRequestsPerMinute(requestsPerMinute))
	vigiloIdentityServer := server.NewVigiloIdentityServer()

	req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Login, bytes.NewBuffer(requestBody))
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)
	return rr
}

func TestRateLimiting(t *testing.T) {
	users.ResetInMemoryUserStore()
	user := users.NewUser("", testEmail, testPassword1)

	request := users.UserLoginRequest{Email: utils.TestEmail, Password: utils.TestPassword1}
	requestBody, err := json.Marshal(request)
	assert.NoError(t, err, "failed to marshal request body")

	userStore := users.GetInMemoryUserStore()
	user := users.NewUser("", utils.TestEmail, utils.TestPassword1)
	hashedPassword, _ := utils.HashPassword(user.Password)
	user.Password = hashedPassword
	_ = userStore.AddUser(user)

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
