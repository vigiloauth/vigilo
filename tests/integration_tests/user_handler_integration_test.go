package integration_tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func setupIdentityServer(endpoint string, body []byte) *httptest.ResponseRecorder {
	vigiloIdentityServer := server.NewVigiloIdentityServer()
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

func TestUserHandler_HandleUserRegistration(t *testing.T) {
	pc := config.NewPasswordConfig(
		config.WithUppercase(),
		config.WithNumber(),
		config.WithSymbol(),
		config.WithMinLength(10),
	)
	config.NewServerConfig(config.WithPasswordConfig(pc))

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
				t.Fatalf("failed to marshal request body: %v", err)
			}

			rr := setupIdentityServer(utils.UserEndpoints.Registration, body)
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
	users.ResetInMemoryUserStore()
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
	hashedPassword, _ := utils.HashPassword(user.Password)
	user.Password = hashedPassword
	userStore.AddUser(user)

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

func TestUserHandler_SuccessfulLogout(t *testing.T) {
	users.ResetInMemoryUserStore()
	userStore := users.GetInMemoryUserStore()
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	hashedPassword, _ := utils.HashPassword(user.Password)
	user.Password = hashedPassword
	userStore.AddUser(user)

	token := simulateLogin(t, utils.TestConstants.Email, utils.TestConstants.Password)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Logout, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	config.NewServerConfig()
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status %v, got %v", http.StatusOK, rr.Code)
	}
}

func TestUserHandler_ProtectedRouteWithExpiredToken(t *testing.T) {
	users.ResetInMemoryUserStore()
	userStore := users.GetInMemoryUserStore()
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	hashedPassword, _ := utils.HashPassword(user.Password)
	user.Password = hashedPassword
	userStore.AddUser(user)

	expiredToken := generateExpiredToken()

	// Create a request to the protected route with the expired token
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Logout, nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)

	config.NewServerConfig()
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %v, got %v", http.StatusUnauthorized, rr.Code)
	}
}

func generateExpiredToken() string {
	expiredTime := time.Now().Add(-1 * time.Hour)
	claims := &jwt.StandardClaims{
		Subject:   utils.TestConstants.Email,
		ExpiresAt: expiredTime.Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString([]byte("secret"))
	if err != nil {
		panic("failed to generate expired token: " + err.Error())
	}
	token.GetInMemoryTokenStore().AddToken(tokenString, utils.TestConstants.Email, expiredTime)
	return tokenString
}

func simulateLogin(t *testing.T, email, password string) string {
	loginRequest := users.NewUserLoginRequest(email, password)
	loginBody, err := json.Marshal(loginRequest)
	if err != nil {
		t.Fatalf("failed to marshal login request body: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Login, bytes.NewBuffer(loginBody))

	config.NewServerConfig()
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %v, got %v", http.StatusOK, rr.Code)
	}

	var loginResponse users.UserLoginResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &loginResponse); err != nil {
		t.Fatalf("failed to unmarshal login response body: %v", err)
	}

	token := loginResponse.JWTToken
	if token == "" {
		t.Fatalf("expected token in login response, got none")
	}

	return token
}
