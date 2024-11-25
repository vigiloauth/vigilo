package tests

import (
	"bytes"
	"encoding/json"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/pkg/identity/server"
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
			name: "Duplicate email during user registration",
			requestBody: users.UserRegistrationRequest{
				Username: username,
				Email:    email,
				Password: password,
			},
			expectedStatus: http.StatusConflict,
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

			if test.name == "Duplicate email during user registration" {
				_ = users.GetUserCache().AddUser(users.User{Username: username, Password: password, Email: email})
			}

			rr := setupIdentityServer(body)
			if rr.Code != test.expectedStatus {
				t.Errorf("expected status %v, got %v", test.expectedStatus, rr.Code)
			}

			if test.wantError {
				var responseBody map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &responseBody); err != nil {
					t.Fatalf("failed to unmarshal response body: %v", err)
				}

				if responseBody["error"] == nil {
					t.Errorf("expected error in response, got none")
				}
			}
		})
	}
}

func setupIdentityServer(body []byte) *httptest.ResponseRecorder {
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	req := httptest.NewRequest(http.MethodPost, "/identity/users", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router.ServeHTTP(rr, req)

	return rr
}
