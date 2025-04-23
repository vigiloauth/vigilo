package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/constants"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	repository "github.com/vigiloauth/vigilo/internal/repository/user"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestUserHandler_RegisterUser_Success(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	requestBody := &users.UserRegistrationRequest{
		Username: testUsername,
		Email:    testEmail,
		Password: testPassword1,
		Role:     constants.AdminRole,
	}

	body, err := json.Marshal(requestBody)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.UserEndpoints.Registration,
		bytes.NewBuffer(body), nil,
	)

	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestUserHandler_RegisterUser_DuplicateEmail(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()
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

func TestUserHandler_VerifyAccount(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		tokenDuration := 5 * time.Minute
		testContext.WithJWTToken(testEmail, time.Duration(tokenDuration))

		endpoint := web.UserEndpoints.Verify + "?token=" + testContext.JWTToken
		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, nil)

		assert.Equal(t, http.StatusOK, rr.Code)

		// assert user account is verified
		userRepo := repository.GetInMemoryUserRepository()
		retrievedUser, err := userRepo.GetUserByEmail(context.Background(), testEmail)
		assert.NoError(t, err)
		assert.True(t, retrievedUser.Verified)
	})

	t.Run("Error is returned when the verification code is missing in the request", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser()
		endpoint := web.UserEndpoints.Verify + "?token="
		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, nil)

		assert.Equal(t, http.StatusBadRequest, rr.Code)

		userRepo := repository.GetInMemoryUserRepository()

		retrievedUser, err := userRepo.GetUserByEmail(context.Background(), testEmail)
		assert.NoError(t, err)
		assert.False(t, retrievedUser.Verified)
	})

	t.Run("Error is returned when the verification code is expired", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		tokenDuration := -5 * time.Minute
		testContext.WithJWTToken(testEmail, time.Duration(tokenDuration))

		endpoint := web.UserEndpoints.Verify + "?token=" + testContext.JWTToken
		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, nil)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		// assert user account is not verified
		userRepo := repository.GetInMemoryUserRepository()
		retrievedUser, err := userRepo.GetUserByEmail(context.Background(), testEmail)
		assert.NoError(t, err)
		assert.False(t, retrievedUser.Verified)
	})

	t.Run("Error is returned when the user does not exist", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		tokenDuration := 5 * time.Minute
		testContext.WithJWTToken("randomUser", time.Duration(tokenDuration))

		endpoint := web.UserEndpoints.Verify + "?token=" + testContext.JWTToken
		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, nil)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}
