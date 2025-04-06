package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestUserHandler_DuplicateEmail(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	testContext.WithUser()
	defer testContext.TearDown()

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
		defer testContext.TearDown()

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
		defer testContext.TearDown()

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
		testContext := NewVigiloTestContext(t)
		testContext.WithUser()
		testContext.WithExpiredToken()
		defer testContext.TearDown()

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
			requestBody, err := json.Marshal(tc.requestBody)
			assert.NoError(t, err)

			rr := testContext.SendHTTPRequest(
				http.MethodPost,
				web.UserEndpoints.RequestPasswordReset,
				bytes.NewBuffer(requestBody),
				nil,
			)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			testContext.TearDown()
		}
	})

	t.Run("Reset Password Invalid requests", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)

		testCases := []struct {
			name           string
			requestBody    users.UserPasswordResetRequest
			expectedStatus int
		}{
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
			testContext.WithUser()
			testContext.WithAccessToken(testUserID, time.Hour)

			requestBody, err := json.Marshal(tc.requestBody)
			assert.NoError(t, err)

			rr := testContext.SendHTTPRequest(
				http.MethodPatch,
				web.UserEndpoints.ResetPassword,
				bytes.NewBuffer(requestBody),
				nil,
			)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			testContext.TearDown()
		}
	})

	t.Run("Successful Password Reset", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithUser()
		testContext.WithAccessToken(testEmail, time.Hour)
		defer testContext.TearDown()

		request := users.UserPasswordResetRequest{Email: testEmail, ResetToken: testContext.JWTToken, NewPassword: testPassword2}
		requestBody, err := json.Marshal(request)

		assert.NoError(t, err)
		rr := testContext.SendHTTPRequest(
			http.MethodPatch,
			web.UserEndpoints.ResetPassword,
			bytes.NewBuffer(requestBody),
			nil,
		)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Reset Password and Login With New Password", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithUser()
		testContext.WithAccessToken(testEmail, time.Hour)
		defer testContext.TearDown()

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
		assert.NoError(t, err)
		oldLoginResp := testContext.SendHTTPRequest(
			http.MethodPost,
			web.UserEndpoints.Login,
			bytes.NewBuffer(requestBody),
			nil,
		)
		assert.Equal(t, http.StatusUnauthorized, oldLoginResp.Code)
	})
}
