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

// TestHelper encapsulates common testing functionality
type TestHelper struct {
	T        *testing.T
	Server   *httptest.Server
	Client   *http.Client
	User     *users.User
	JWTToken string
}

// setup prepares the environment for a test with default configuration
func setup(t *testing.T) *TestHelper {
	users.ResetInMemoryUserStore()
	config.NewServerConfig()
	return &TestHelper{
		T:      t,
		Client: &http.Client{},
	}
}

// setupServer creates a test helper with a running test server
func setupServer(t *testing.T) *TestHelper {
	helper := setup(t)
	helper.Server = httptest.NewServer(server.NewVigiloIdentityServer().Router())
	return helper
}

// createTestUser creates a test user with default credentials
func (h *TestHelper) createTestUser() *users.User {
	user := users.NewUser(testUsername, testEmail, testPassword1)
	hashedPassword, err := utils.HashPassword(user.Password)
	assert.NoError(h.T, err)
	user.Password = hashedPassword
	users.GetInMemoryUserStore().AddUser(user)
	h.User = user
	return user
}

// sendRequest is a helper to send HTTP requests to the test server
func (h *TestHelper) sendRequest(method, endpoint string, body any) *http.Response {
	var bodyReader *bytes.Buffer

	if body != nil {
		jsonBody, err := json.Marshal(body)
		assert.NoError(h.T, err)
		bodyReader = bytes.NewBuffer(jsonBody)
	} else {
		bodyReader = bytes.NewBuffer(nil)
	}

	var url string
	if h.Server != nil {
		url = h.Server.URL + endpoint
	} else {
		url = endpoint // For direct test recorder usage
	}

	req, err := http.NewRequest(method, url, bodyReader)
	assert.NoError(h.T, err)
	req.Header.Set("Content-Type", "application/json")

	if h.JWTToken != "" {
		req.Header.Set("Authorization", "Bearer "+h.JWTToken)
	}

	resp, err := h.Client.Do(req)
	assert.NoError(h.T, err)
	return resp
}

// generateExpiredToken creates an expired JWT token for testing
func (h *TestHelper) generateExpiredToken() string {
	expiredTime := time.Now().Add(-1 * time.Hour)
	claims := &jwt.StandardClaims{
		Subject:   testEmail,
		ExpiresAt: expiredTime.Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := jwtToken.SignedString([]byte("secret"))
	assert.NoError(h.T, err)

	token.GetInMemoryTokenStore().AddToken(tokenString, testEmail, expiredTime)
	return tokenString
}

// setupResetToken generates a password reset token for the current user
func (h *TestHelper) setupResetToken(duration time.Duration) string {
	tokenService := token.NewTokenService(token.GetInMemoryTokenStore())
	resetToken, err := tokenService.GenerateToken(testEmail, duration)
	assert.NoError(h.T, err)

	token.GetInMemoryTokenStore().AddToken(resetToken, testEmail, time.Now().Add(duration))
	return resetToken
}

// checkErrorResponse verifies that the response contains an error
func checkErrorResponse(t *testing.T, responseBody []byte) {
	var response map[string]any
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	assert.NotNil(t, response["error_code"], "expected error in response, got none")
}

func TestUserHandler_UserRegistration(t *testing.T) {
	setup(t)
	// Configure password requirements
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
			requestBody:    *users.NewUserRegistrationRequest(testUsername, testEmail, testPassword1),
			expectedStatus: http.StatusCreated,
			wantError:      false,
		},
		{
			name:           "User Registration fails given invalid request body",
			requestBody:    *users.NewUserRegistrationRequest("", "invalid-email", testPassword1),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Missing required fields in request",
			requestBody:    *users.NewUserRegistrationRequest(testUsername, "", ""),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Invalid password length",
			requestBody:    *users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contains an uppercase letter",
			requestBody:    *users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contain a number",
			requestBody:    *users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contain a symbol",
			requestBody:    *users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.requestBody)
			assert.NoError(t, err)

			vigiloIdentityServer := server.NewVigiloIdentityServer()
			req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Registration, bytes.NewBuffer(body))
			rr := httptest.NewRecorder()
			vigiloIdentityServer.Router().ServeHTTP(rr, req)

			assert.Equal(t, test.expectedStatus, rr.Code)

			if test.wantError {
				checkErrorResponse(t, rr.Body.Bytes())
			}
		})
	}
}

func TestUserHandler_DuplicateEmail(t *testing.T) {
	helper := setup(t)
	helper.createTestUser()

	requestBody := users.NewUserRegistrationRequest(testUsername, testEmail, testPassword1)
	body, err := json.Marshal(requestBody)
	assert.NoError(t, err)

	vigiloIdentityServer := server.NewVigiloIdentityServer()
	req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Registration, bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestUserHandler_UserAuthentication(t *testing.T) {
	t.Run("Successful Login", func(t *testing.T) {
		helper := setup(t)
		helper.createTestUser()

		requestBody := users.NewUserLoginRequest(testEmail, testPassword1)
		body, err := json.Marshal(requestBody)
		assert.NoError(t, err)

		vigiloIdentityServer := server.NewVigiloIdentityServer()
		req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Login, bytes.NewBuffer(body))
		rr := httptest.NewRecorder()
		vigiloIdentityServer.Router().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Successful Logout", func(t *testing.T) {
		helper := setup(t)
		helper.createTestUser()

		// Login to get token
		loginRequest := users.NewUserLoginRequest(testEmail, testPassword1)
		body, err := json.Marshal(loginRequest)
		assert.NoError(t, err)

		vigiloIdentityServer := server.NewVigiloIdentityServer()
		loginReq := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Login, bytes.NewBuffer(body))
		loginRR := httptest.NewRecorder()
		vigiloIdentityServer.Router().ServeHTTP(loginRR, loginReq)

		var loginResponse users.UserLoginResponse
		err = json.Unmarshal(loginRR.Body.Bytes(), &loginResponse)
		assert.NoError(t, err)

		// Use token to logout
		logoutReq := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Logout, nil)
		logoutReq.Header.Set("Authorization", "Bearer "+loginResponse.JWTToken)
		logoutRR := httptest.NewRecorder()
		vigiloIdentityServer.Router().ServeHTTP(logoutRR, logoutReq)

		assert.Equal(t, http.StatusOK, logoutRR.Code)
	})

	t.Run("Protected Route With Expired Token", func(t *testing.T) {
		helper := setup(t)
		helper.createTestUser()
		expiredToken := helper.generateExpiredToken()

		vigiloIdentityServer := server.NewVigiloIdentityServer()
		req := httptest.NewRequest(http.MethodPost, utils.UserEndpoints.Logout, nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		rr := httptest.NewRecorder()
		vigiloIdentityServer.Router().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestUserHandler_PasswordReset(t *testing.T) {
	t.Run("Request Password Reset Email", func(t *testing.T) {
		helper := setupServer(t)
		defer helper.Server.Close()

		testCases := []struct {
			name           string
			requestBody    users.UserPasswordResetRequest
			expectedStatus int
			expectedBody   string
		}{
			{
				name:           "Successful Request",
				requestBody:    users.UserPasswordResetRequest{Email: testEmail},
				expectedStatus: http.StatusOK,
				expectedBody:   `{"message":"Password reset instructions have been sent to your email if an account exists."}`,
			},
			{
				name:           "Invalid Request Body",
				requestBody:    users.UserPasswordResetRequest{},
				expectedStatus: http.StatusUnprocessableEntity,
				expectedBody:   `{"error_code":"invalid_format", "message":"email is malformed or missing"}`,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				resp := helper.sendRequest(http.MethodPost, utils.UserEndpoints.RequestPasswordReset, tc.requestBody)
				defer resp.Body.Close()

				assert.Equal(t, tc.expectedStatus, resp.StatusCode)

				buf := new(bytes.Buffer)
				_, err := buf.ReadFrom(resp.Body)
				assert.NoError(t, err)
				assert.JSONEq(t, tc.expectedBody, buf.String())
			})
		}
	})

	t.Run("Reset Password", func(t *testing.T) {
		helper := setupServer(t)
		defer helper.Server.Close()
		helper.createTestUser()
		resetToken := helper.setupResetToken(time.Hour)

		testCases := []struct {
			name           string
			requestBody    users.UserPasswordResetRequest
			expectedStatus int
		}{
			{
				name:           "Successful Reset",
				requestBody:    users.UserPasswordResetRequest{Email: testEmail, ResetToken: resetToken, NewPassword: testPassword2},
				expectedStatus: http.StatusOK,
			},
			{
				name:           "Invalid Request Body",
				requestBody:    users.UserPasswordResetRequest{Email: testEmail},
				expectedStatus: http.StatusBadRequest,
			},
			{
				name:           "Invalid token",
				requestBody:    users.UserPasswordResetRequest{Email: testEmail, ResetToken: "invalid", NewPassword: testPassword2},
				expectedStatus: http.StatusUnauthorized,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				resp := helper.sendRequest(http.MethodPatch, utils.UserEndpoints.ResetPassword, tc.requestBody)
				defer resp.Body.Close()

				assert.Equal(t, tc.expectedStatus, resp.StatusCode)
			})
		}
	})

	t.Run("Reset Password and Login With New Password", func(t *testing.T) {
		helper := setupServer(t)
		defer helper.Server.Close()
		helper.createTestUser()
		resetToken := helper.setupResetToken(time.Hour)

		// Reset the password
		resetRequest := users.UserPasswordResetRequest{
			Email:       testEmail,
			ResetToken:  resetToken,
			NewPassword: testPassword2,
		}

		resetResp := helper.sendRequest(http.MethodPatch, utils.UserEndpoints.ResetPassword, resetRequest)
		defer resetResp.Body.Close()
		assert.Equal(t, http.StatusOK, resetResp.StatusCode)

		// Attempt login with new password
		loginRequest := users.NewUserLoginRequest(testEmail, testPassword2)
		loginResp := helper.sendRequest(http.MethodPost, utils.UserEndpoints.Login, loginRequest)
		defer loginResp.Body.Close()
		assert.Equal(t, http.StatusOK, loginResp.StatusCode)

		// Verify JWT token in response
		var loginResponse users.UserLoginResponse

		err := json.NewDecoder(loginResp.Body).Decode(&loginResponse)
		assert.NoError(t, err)
		assert.NotEmpty(t, loginResponse.JWTToken)

		// Attempt login with old password
		oldLoginRequest := users.NewUserLoginRequest(testEmail, testPassword1)
		oldLoginResp := helper.sendRequest(http.MethodPost, utils.UserEndpoints.Login, oldLoginRequest)
		defer oldLoginResp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, oldLoginResp.StatusCode)
	})
}
