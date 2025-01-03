package integration_tests

import (
	"bytes"
	"encoding/json"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/users"
	"net/http"
	"net/http/httptest"
	"testing"
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
			requestBody:    *users.NewUserRegistrationRequest(users.TestConstants.Username, users.TestConstants.Email, users.TestConstants.Password),
			expectedStatus: http.StatusCreated,
			wantError:      false,
		},
		{
			name:           "User Registration fails given invalid request body",
			requestBody:    *users.NewUserRegistrationRequest("", "invalidemail", users.TestConstants.Password),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Missing required fields in request",
			requestBody:    *users.NewUserRegistrationRequest(users.TestConstants.Username, "", ""),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Invalid password length",
			requestBody:    *users.NewUserRegistrationRequest(users.TestConstants.Username, users.TestConstants.Email, users.TestConstants.InvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contains an uppercase letter",
			requestBody:    *users.NewUserRegistrationRequest(users.TestConstants.Username, users.TestConstants.Email, users.TestConstants.InvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contain a number",
			requestBody:    *users.NewUserRegistrationRequest(users.TestConstants.Username, users.TestConstants.Email, users.TestConstants.InvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contain a symbol",
			requestBody:    *users.NewUserRegistrationRequest(users.TestConstants.Username, users.TestConstants.Email, users.TestConstants.InvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.requestBody)
			if err != nil {
				t.Fatalf("failed to  marshal request body: %v", err)
			}

			rr := setupIdentityServer(body)
			if rr.Code != test.expectedStatus {
				t.Errorf("expected status %v, got %v", test.expectedStatus, rr.Code)
			}

			if test.wantError {
				checkErrorResponse(t, rr.Body.Bytes())
			}
		})
	}
}

func TestUserHandler_DuplicateEmail(t *testing.T) {
	requestBody := users.NewUserRegistrationRequest(users.TestConstants.Username, users.TestConstants.Email, users.TestConstants.Password)
	user := users.NewUser(users.TestConstants.Username, users.TestConstants.Email, users.TestConstants.Password)
	_ = users.GetInMemoryUserStore().AddUser(*user)

	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	responseRecorder := setupIdentityServer(body)
	if responseRecorder.Code != http.StatusConflict {
		t.Errorf("expected status %v, got %v", http.StatusConflict, responseRecorder.Code)
	}
}

func setupIdentityServer(body []byte) *httptest.ResponseRecorder {
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	req := httptest.NewRequest(http.MethodPost, users.UserEndpoints.Registration, bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	return rr
}

func checkErrorResponse(t *testing.T, responseBody []byte) {
	var response map[string]interface{}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}

	if response["error_code"] == nil {
		t.Errorf("expected error in response, got none")
	}
}
