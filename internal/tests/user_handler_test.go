package tests

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

const (
	username string = "username"
	email    string = "email@email.com"
	password string = "Pa$sword_123"
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
				Password: password,
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
		{
			name: "Invalid password length",
			requestBody: users.UserRegistrationRequest{
				Username: username,
				Email:    email,
				Password: "password",
			},
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name: "Password does not contains an uppercase letter",
			requestBody: users.UserRegistrationRequest{
				Username: username,
				Email:    email,
				Password: "password",
			},
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name: "Password does not contain a number",
			requestBody: users.UserRegistrationRequest{
				Username: username,
				Email:    email,
				Password: "password",
			},
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name: "Password does not contain a symbol",
			requestBody: users.UserRegistrationRequest{
				Username: username,
				Email:    email,
				Password: "password",
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
				var responseBody map[string]interface{}
				if err := json.Unmarshal(rr.Body.Bytes(), &responseBody); err != nil {
					t.Fatalf("failed to unmarshal response body: %v", err)
				}

				if responseBody["error_code"] == nil {
					t.Errorf("expected error in response, got none")
				}
			}
		})
	}
}

func TestUserHandler_DuplicateEmail(t *testing.T) {
	requestBody := users.UserRegistrationRequest{
		Username: username,
		Email:    email,
		Password: password,
	}

	_ = users.GetInMemoryUserStore().AddUser(users.User{Username: username, Email: email})
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatalf("failed to marshal request body: %v", err)
	}

	rr := setupIdentityServer(body)
	if rr.Code != http.StatusConflict {
		t.Errorf("expected status %v, got %v", http.StatusConflict, rr.Code)
	}
}

func setupIdentityServer(body []byte) *httptest.ResponseRecorder {
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	req := httptest.NewRequest(http.MethodPost, "/vigilo/identity/users", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router.ServeHTTP(rr, req)

	return rr
}
