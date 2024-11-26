package tests

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/users"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	username string = "username"
	email    string = "email@email.com"
	password string = "password"
)

func TestUserHandler_HandleUserRegistration(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    users.UserRegistrationRequest
		expectedStatus int
		wantError      bool
	}{
		{
			name: "Successful User Registration",
			requestBody: users.UserRegistrationRequest{
				Username: username,
				Email:    email,
				Password: password,
			},
			expectedStatus: http.StatusCreated,
			wantError:      false,
		},
		{
			name: "User Registration fails given invalid request body",
			requestBody: users.UserRegistrationRequest{
				Username: "",
				Email:    "invalidemail",
				Password: "short",
			},
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name: "Missing required fields in request",
			requestBody: users.UserRegistrationRequest{
				Username: "missingemailuser",
			},
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

func TestUserHandler_DuplicateUser(t *testing.T) {
	requestBody := users.UserRegistrationRequest{Username: username, Email: email, Password: password}
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("failed to  marshal request body: %v", err)
	}

	_ = users.GetInMemoryUserStore().AddUser(users.User{Username: username, Password: password, Email: email})

	rr := setupIdentityServer(body)
	assert.Equal(t, http.StatusConflict, rr.Code)
}

func setupIdentityServer(body []byte) *httptest.ResponseRecorder {
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	req := httptest.NewRequest(http.MethodPost, "/identity/users", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router.ServeHTTP(rr, req)

	return rr
}

func checkErrorResponse(t *testing.T, responseBody []byte) {
	var response map[string]interface{}
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}

	if response["error"] == nil {
		t.Errorf("expected error in response, got none")
	}
}
