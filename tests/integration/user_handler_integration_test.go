package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

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
