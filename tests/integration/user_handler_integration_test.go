package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	repository "github.com/vigiloauth/vigilo/v2/internal/repository/user"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

func TestUserHandler_RegisterUser_Success(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	requestBody := testContext.GetUserRegistrationRequest()

	body, err := json.Marshal(requestBody)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.UserEndpoints.Registration,
		bytes.NewBuffer(body), nil,
	)

	assert.Equal(t, http.StatusCreated, rr.Code)
}

func TestUserHandler_OAuthLogin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})
		testContext.WithClient(
			client.Confidential,
			[]string{constants.ClientManageScope, constants.UserManageScope},
			[]string{constants.AuthorizationCodeGrantType},
		)

		loginRequest := users.UserLoginRequest{
			Username: testUsername,
			Password: testPassword1,
		}

		requestBody, err := json.Marshal(loginRequest)
		assert.NoError(t, err)

		queryParams := url.Values{}
		queryParams.Add(constants.ClientIDReqField, testClientID)
		queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
		endpoint := web.OAuthEndpoints.Authenticate + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			endpoint,
			bytes.NewReader(requestBody), nil,
		)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Invalid UserLogin request", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Confidential,
			[]string{constants.ClientManageScope, constants.UserManageScope},
			[]string{constants.AuthorizationCodeGrantType},
		)

		loginRequest := users.UserLoginRequest{
			Username: testUsername,
			Password: testPassword1,
		}

		requestBody, err := json.Marshal(loginRequest)
		assert.NoError(t, err)

		queryParams := url.Values{}
		queryParams.Add(constants.ClientIDReqField, testClientID)
		queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
		endpoint := web.OAuthEndpoints.Authenticate + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			endpoint,
			bytes.NewReader(requestBody), nil,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestUserHandler_RegisterUser_DuplicateEmail(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()
	testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})

	requestBody := users.NewUserRegistrationRequest(testUsername, testEmail, testPassword1)
	requestBody.Birthdate = testBirthdate

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
		defer testContext.TearDown()

		testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})
		requestBody := users.NewUserLoginRequest(testUsername, testPassword1)
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

	t.Run("Protected Route With Expired Token", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})
		testContext.WithExpiredToken()

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
		assert.True(t, retrievedUser.EmailVerified)
	})

	t.Run("Error is returned when the verification code is missing in the request", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})
		endpoint := web.UserEndpoints.Verify + "?token="
		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, nil)

		assert.Equal(t, http.StatusBadRequest, rr.Code)

		userRepo := repository.GetInMemoryUserRepository()

		retrievedUser, err := userRepo.GetUserByEmail(context.Background(), testEmail)
		assert.NoError(t, err)
		assert.False(t, retrievedUser.EmailVerified)
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
		assert.False(t, retrievedUser.EmailVerified)
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
