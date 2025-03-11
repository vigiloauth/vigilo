package integration_tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

const (
	userEmail   string = "test@email.com"
	username    string = "username"
	password    string = "Pa$s_W0Rd_"
	newPassword string = "__Pa$$_w0rD"
)

func setupTest() {
	users.ResetInMemoryUserStore()
	config.NewServerConfig()
}

func setupIdentityServer(endpoint string, body []byte) *httptest.ResponseRecorder {
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	req := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)
	return rr
}

func TestUserHandler_HandleUserRegistration(t *testing.T) {
	setupTest()
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
			body, err := json.Marshal(test.requestBody)
			assert.NoError(t, err)

			rr := setupIdentityServer(utils.UserEndpoints.Registration, body)
			assert.Equal(t, test.expectedStatus, rr.Code)

			if test.wantError {
				checkErrorResponse(t, rr.Body.Bytes())
			}
		})
	}
}

func TestUserHandler_DuplicateEmail(t *testing.T) {
	setupTest()
	requestBody := users.NewUserRegistrationRequest(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	createTestUser(t)

	body, err := json.Marshal(requestBody)
	assert.NoError(t, err)

	rr := setupIdentityServer(utils.UserEndpoints.Registration, body)
	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestUserHandler_SuccessfulUserLogin(t *testing.T) {
	setupTest()
	createTestUser(t)

	requestBody := users.NewUserLoginRequest(utils.TestConstants.Email, utils.TestConstants.Password)
	body, err := json.Marshal(requestBody)
	assert.NoError(t, err)

	rr := setupIdentityServer(utils.UserEndpoints.Login, body)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestUserHandler_SuccessfulLogout(t *testing.T) {
	setupTest()
	createTestUser(t)
	token := simulateLogin(t, utils.TestConstants.Email, utils.TestConstants.Password)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Logout, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	vigiloIdentityServer := server.NewVigiloIdentityServer()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestUserHandler_ProtectedRouteWithExpiredToken(t *testing.T) {
	setupTest()
	createTestUser(t)
	expiredToken := generateExpiredToken()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Logout, nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)

	vigiloIdentityServer := server.NewVigiloIdentityServer()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestUserHandler_RequestPasswordResetEmail(t *testing.T) {
	testServer := httptest.NewServer(server.NewVigiloIdentityServer().Router())
	defer testServer.Close()
	users.ResetInMemoryUserStore()

	testCases := []struct {
		name           string
		requestBody    users.UserPasswordResetRequest
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "Successful Request",
			requestBody:    users.UserPasswordResetRequest{Email: "test@example.com"},
			expectedStatus: http.StatusOK,
			expectedBody:   `{"message":"Password reset instructions have been sent to your email if an account exists."}`,
		},
		{
			name:           "Invalid Request Body",
			requestBody:    users.UserPasswordResetRequest{},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"description":"malformed or missing field", "error":"email: malformed or missing field", "error_code":"INVALID_FORMAT"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.requestBody)
			assert.NoError(t, err)

			url := testServer.URL + utils.UserEndpoints.RequestPasswordReset
			resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
			assert.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			buf := new(bytes.Buffer)
			_, err = buf.ReadFrom(resp.Body)
			assert.NoError(t, err)
			assert.JSONEq(t, tc.expectedBody, buf.String())
		})
	}
}

func TestUserHandler_ResetPassword(t *testing.T) {
	testServer := httptest.NewServer(server.NewVigiloIdentityServer().Router())
	defer testServer.Close()

	user := users.NewUser(username, userEmail, password)
	users.GetInMemoryUserStore().AddUser(user)

	tokenService := token.NewTokenService(token.GetInMemoryTokenStore())
	resetToken, err := tokenService.GenerateToken(userEmail, time.Hour)
	token.GetInMemoryTokenStore().AddToken(resetToken, userEmail, time.Now().Add(time.Hour))
	assert.NoError(t, err)

	testCases := []struct {
		name           string
		requestBody    users.UserPasswordResetRequest
		expectedStatus int
	}{
		{
			name:           "Successful Reset",
			requestBody:    users.UserPasswordResetRequest{Email: userEmail, ResetToken: resetToken, NewPassword: newPassword},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid Request Body",
			requestBody:    users.UserPasswordResetRequest{Email: userEmail},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Invalid token",
			requestBody:    users.UserPasswordResetRequest{Email: userEmail, ResetToken: "invalid", NewPassword: newPassword},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.requestBody)
			assert.NoError(t, err)

			url := testServer.URL + utils.UserEndpoints.ResetPassword
			req, err := http.NewRequest(http.MethodPatch, url, bytes.NewBuffer(body))
			assert.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			assert.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.expectedStatus, resp.StatusCode)

			buf := new(bytes.Buffer)
			_, err = buf.ReadFrom(resp.Body)
			assert.NoError(t, err)
		})
	}
}

func checkErrorResponse(t *testing.T, responseBody []byte) {
	var response map[string]any
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	assert.NotNil(t, response["error_code"], "expected error in response, got none")
}

func createTestUser(t *testing.T) *users.User {
	user := users.NewUser(utils.TestConstants.Username, utils.TestConstants.Email, utils.TestConstants.Password)
	hashedPassword, err := utils.HashPassword(user.Password)
	assert.NoError(t, err)
	user.Password = hashedPassword
	users.GetInMemoryUserStore().AddUser(user)
	return user
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
	body, err := json.Marshal(loginRequest)
	assert.NoError(t, err)

	rr := setupIdentityServer(utils.UserEndpoints.Login, body)
	assert.Equal(t, http.StatusOK, rr.Code)

	var loginResponse users.UserLoginResponse
	err = json.Unmarshal(rr.Body.Bytes(), &loginResponse)
	assert.NoError(t, err)
	assert.NotEmpty(t, loginResponse.JWTToken, "expected token in login response, got none")

	return loginResponse.JWTToken
}
