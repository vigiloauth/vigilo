package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestUserHandler_UserRegistration(t *testing.T) {
	// Configure password requirements
	pc := config.NewPasswordConfig(
		config.WithUppercase(),
		config.WithNumber(),
		config.WithSymbol(),
		config.WithMinLength(10),
	)

	testContext := NewVigiloTestContext(t)
	testContext.WithCustomConfig(config.WithPasswordConfig(pc))

	tests := []struct {
		name           string
		requestBody    *users.UserRegistrationRequest
		expectedStatus int
		wantError      bool
	}{
		{
			name:           "Successful User Registration",
			requestBody:    users.NewUserRegistrationRequest(testUsername, testEmail, testPassword1),
			expectedStatus: http.StatusCreated,
			wantError:      false,
		},
		{
			name:           "User Registration fails given invalid request body",
			requestBody:    users.NewUserRegistrationRequest("", "invalid-email", testPassword1),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Missing required fields in request",
			requestBody:    users.NewUserRegistrationRequest(testUsername, "", ""),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Invalid password length",
			requestBody:    users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contains an uppercase letter",
			requestBody:    users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contain a number",
			requestBody:    users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
		{
			name:           "Password does not contain a symbol",
			requestBody:    users.NewUserRegistrationRequest(testUsername, testEmail, testInvalidPassword),
			expectedStatus: http.StatusBadRequest,
			wantError:      true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := json.Marshal(test.requestBody)
			assert.NoError(t, err)

			rr := testContext.SendHTTPRequest(
				http.MethodPost,
				web.UserEndpoints.Registration,
				bytes.NewReader(body),
				nil,
			)

			assert.Equal(t, test.expectedStatus, rr.Code)
		})
	}
}

func TestUserHandler_DuplicateEmail(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	testContext.WithUser()

	requestBody := users.NewUserRegistrationRequest(testUsername, testEmail, testPassword1)
	body, err := json.Marshal(requestBody)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.UserEndpoints.Registration,
		bytes.NewBuffer(body),
		nil,
	)

	assert.Equal(t, http.StatusConflict, rr.Code)
}

func TestUserHandler_UserAuthentication(t *testing.T) {
	t.Run("Successful Login", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithUser()

		requestBody := users.NewUserLoginRequest(testUserID, testEmail, testPassword1)
		body, err := json.Marshal(requestBody)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.UserEndpoints.Login,
			bytes.NewBuffer(body),
			nil,
		)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Successful Logout", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithUser()

		// Login to get token
		loginRequest := users.NewUserLoginRequest(testUserID, testEmail, testPassword1)
		body, err := json.Marshal(loginRequest)
		assert.NoError(t, err)

		loginRR := testContext.SendHTTPRequest(
			http.MethodPost,
			web.UserEndpoints.Login,
			bytes.NewBuffer(body),
			nil,
		)

		var loginResponse users.UserLoginResponse
		err = json.Unmarshal(loginRR.Body.Bytes(), &loginResponse)
		assert.NoError(t, err)

		headers := map[string]string{"Authorization": "Bearer " + loginResponse.JWTToken}
		// Use token to logout
		logoutRR := testContext.SendHTTPRequest(
			http.MethodPost,
			web.UserEndpoints.Logout,
			nil,
			headers,
		)

		assert.Equal(t, http.StatusOK, logoutRR.Code)
	})

	t.Run("Protected Route With Expired Token", func(t *testing.T) {
		testContext := NewVigiloTestContext(t).
			WithUser().
			WithExpiredToken()

		rr := testContext.SendHTTPRequest(http.MethodPost, web.UserEndpoints.Logout, nil, nil)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestUserHandler_PasswordReset(t *testing.T) {
	t.Run("Request Password Reset Email", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)

		testCases := []struct {
			name           string
			requestBody    users.UserPasswordResetRequest
			expectedStatus int
		}{
			{
				name:           "Successful Request",
				requestBody:    users.UserPasswordResetRequest{Email: testEmail},
				expectedStatus: http.StatusOK,
			},
			{
				name:           "Invalid Request Body",
				requestBody:    users.UserPasswordResetRequest{},
				expectedStatus: http.StatusUnprocessableEntity,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				requestBody, err := json.Marshal(tc.requestBody)
				assert.NoError(t, err)

				rr := testContext.SendHTTPRequest(
					http.MethodPost,
					web.UserEndpoints.RequestPasswordReset,
					bytes.NewBuffer(requestBody),
					nil,
				)

				assert.Equal(t, tc.expectedStatus, rr.Code)
			})
		}
	})

	t.Run("Reset Password", func(t *testing.T) {
		testContext := NewVigiloTestContext(t).
			WithUser().
			WithAccessToken(testEmail, time.Hour)

		testCases := []struct {
			name           string
			requestBody    users.UserPasswordResetRequest
			expectedStatus int
		}{
			{
				name:           "Successful Reset",
				requestBody:    users.UserPasswordResetRequest{Email: testEmail, ResetToken: testContext.JWTToken, NewPassword: testPassword2},
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
				requestBody, err := json.Marshal(tc.requestBody)
				assert.NoError(t, err)

				rr := testContext.SendHTTPRequest(
					http.MethodPatch,
					web.UserEndpoints.ResetPassword,
					bytes.NewBuffer(requestBody),
					nil,
				)

				assert.Equal(t, tc.expectedStatus, rr.Code)
			})
		}
	})

	t.Run("Reset Password and Login With New Password", func(t *testing.T) {
		testContext := NewVigiloTestContext(t).
			WithUser().
			WithAccessToken(testEmail, time.Hour)

		// Reset the password
		resetRequest := users.UserPasswordResetRequest{
			Email:       testEmail,
			ResetToken:  testContext.JWTToken,
			NewPassword: testPassword2,
		}

		requestBody, err := json.Marshal(resetRequest)
		assert.NoError(t, err)

		resetResp := testContext.SendHTTPRequest(
			http.MethodPatch,
			web.UserEndpoints.ResetPassword,
			bytes.NewBuffer(requestBody),
			nil,
		)
		assert.Equal(t, http.StatusOK, resetResp.Code)

		// Attempt to login with new password
		loginRequest := users.NewUserLoginRequest(testUserID, testEmail, testPassword2)
		requestBody, err = json.Marshal(loginRequest)
		assert.NoError(t, err)
		loginResp := testContext.SendHTTPRequest(
			http.MethodPost,
			web.UserEndpoints.Login,
			bytes.NewBuffer(requestBody),
			nil,
		)
		assert.Equal(t, http.StatusOK, loginResp.Code)

		// Verify JWT token in response
		var loginResponse users.UserLoginResponse
		err = json.NewDecoder(loginResp.Body).Decode(&loginResponse)
		assert.NoError(t, err)
		assert.NotEmpty(t, loginResponse.JWTToken)

		// Attempt to login with old password
		oldLoginRequest := users.NewUserLoginRequest(testUserID, testEmail, testPassword1)
		requestBody, err = json.Marshal(oldLoginRequest)
		oldLoginResp := testContext.SendHTTPRequest(
			http.MethodPost,
			web.UserEndpoints.Login,
			bytes.NewBuffer(requestBody),
			nil,
		)
		assert.Equal(t, http.StatusUnauthorized, oldLoginResp.Code)
	})
}
