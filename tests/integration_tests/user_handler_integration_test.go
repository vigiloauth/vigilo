package integration_tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/security"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func TestUserHandler_HandleUserRegistration(t *testing.T) {
	config.GetPasswordConfiguration().
		SetRequireUppercase(true).
		SetRequireNumber(true).
		SetRequireSymbol(true).
		SetMinimumLength(10).
		Build()

	tests := []struct {
		name           string
		requestBody    users.UserRegistrationRequest
		expectedStatus int
		wantError      bool
	}{
		{
			name:           "Successful User Registration",
			requestBody:    *users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password),
			expectedStatus: http.StatusCreated,
			wantError:      false,
		},
		{
			name:           "User Registration fails given invalid request body",
			requestBody:    *users.NewUserRegistrationRequest("", "invalidemail", utils.TestConstants.Password),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Missing required fields in request",
			requestBody:    *users.NewUserRegistrationRequest(utils.TestConstants.Username, "", ""),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Invalid password length",
			requestBody:    *users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contains an uppercase letter",
			requestBody:    *users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contain a number",
			requestBody:    *users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contain a symbol",
			requestBody:    *users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.InvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			users.ResetInMemoryUserStore()
			body, err := json.Marshal(test.requestBody)
			if err != nil {
				t.Fatalf("failed to  marshal request body: %v", err)
			}

			rr := setupIdentityServer(utils.UserEndpoints.Registration, body)
			if rr.Code != test.expectedStatus {
				t.Errorf("expected status %v, got %v", test.expectedStatus, rr.Code)
			}

			fmt.Printf("Response: %v\n", rr.Body.String())
			if test.wantError {
				checkErrorResponse(t, rr.Body.Bytes())
			}
		})
	}
}

func TestUserHandler_DuplicateEmail(t *testing.T) {
	requestBody := users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	_ = users.GetInMemoryUserStore().AddUser(user)

	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	rr := setupIdentityServer(utils.UserEndpoints.Registration, body)
	if rr.Code != http.StatusConflict {
		t.Errorf("expected status %v, got %v", http.StatusConflict, rr.Code)
	}
}

func TestUserHandler_SuccessfulUserLogin(t *testing.T) {
	users.ResetInMemoryUserStore()
	userStore := users.GetInMemoryUserStore()
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	hashedPassword, _ := security.HashPassword(user.Password)
	user.Password = hashedPassword
	userStore.AddUser(user)

	_ = userStore.AddUser(user)
	requestBody := users.NewUserLoginRequest(utils.TestConstants.Email, utils.TestConstants.Password)
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	rr := setupIdentityServer(utils.UserEndpoints.Login, body)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status %v, got %v", http.StatusOK, rr.Code)
	}
}

func setupIdentityServer(endpoint string, body []byte) *httptest.ResponseRecorder {
	serverConfig := config.NewDefaultServerConfig()
	vigiloIdentityServer := server.NewVigiloIdentityServer(serverConfig)
	req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	return rr
}

func checkErrorResponse(t *testing.T, responseBody []byte) {
	var response map[string]any
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}

	if response["error_code"] == nil {
		t.Errorf("expected error in response, got none")
	}
}
