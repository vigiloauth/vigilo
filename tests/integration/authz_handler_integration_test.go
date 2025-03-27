package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestAuthorizationHandler_AuthorizeClient_Success(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage, client.UserManage},
		[]string{client.AuthorizationCode},
	)
	testContext.WithUser()
	testContext.WithUserSession()

	// Call AuthorizeClient Endpoint
	testContext.WithUserConsent()
	queryParams := url.Values{}
	queryParams.Add(common.ClientID, testClientID)
	queryParams.Add(common.RedirectURI, testRedirectURI)
	queryParams.Add(common.Scope, testScope)
	queryParams.Add(common.Approved, fmt.Sprintf("%v", testConsentApproved))

	sessionCookie := testContext.GetSessionCookie()
	headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
	endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

	rr := testContext.SendHTTPRequest(
		http.MethodGet,
		endpoint,
		nil, headers,
	)

	assert.Equal(t, http.StatusFound, rr.Code)
}

func TestAuthorizationHandler_AuthorizeClient_ErrorRetrievingUserIDFromSession(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage, client.UserManage},
		[]string{client.AuthorizationCode},
	)
	testContext.WithUser()
	testContext.WithUserSession()

	// Call AuthorizeClient Endpoint
	testContext.WithUserConsent()
	queryParams := url.Values{}
	queryParams.Add(common.ClientID, testClientID)
	queryParams.Add(common.RedirectURI, testRedirectURI)
	queryParams.Add(common.Scope, testScope)
	queryParams.Add(common.Approved, fmt.Sprintf("%v", testConsentApproved))

	endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()
	rr := testContext.SendHTTPRequest(
		http.MethodGet,
		endpoint,
		nil, nil,
	)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestAuthorizationHandler_AuthorizeClient_NewLoginRequiredError_IsReturned(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage, client.UserManage},
		[]string{client.AuthorizationCode},
	)
	testContext.WithUser()
	testContext.WithUserConsent()

	// Call AuthorizeClient Endpoint
	queryParams := url.Values{}
	queryParams.Add(common.ClientID, testClientID)
	queryParams.Add(common.RedirectURI, testRedirectURI)
	queryParams.Add(common.Scope, testScope)
	queryParams.Add(common.Approved, fmt.Sprintf("%v", testConsentApproved))

	endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()
	rr := testContext.SendHTTPRequest(
		http.MethodGet,
		endpoint,
		nil, nil,
	)

	fmt.Println("BODY:", rr.Body)
	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestAuthorizationHandler_AuthorizeClient_ConsentNotApproved(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage, client.UserManage},
		[]string{client.AuthorizationCode},
	)
	testContext.WithUser()
	testContext.WithUserSession()
	testContext.WithUserConsent()

	// Call AuthorizeClient Endpoint
	queryParams := url.Values{}
	queryParams.Add(common.ClientID, testClientID)
	queryParams.Add(common.RedirectURI, testRedirectURI)
	queryParams.Add(common.Scope, testScope)
	queryParams.Add(common.Approved, "false")

	sessionCookie := testContext.GetSessionCookie()
	headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
	endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

	rr := testContext.SendHTTPRequest(
		http.MethodGet,
		endpoint,
		nil, headers,
	)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestAuthorizationHandler_AuthorizeClient_ErrorIsReturnedCheckingUserConsent(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage, client.UserManage},
		[]string{client.AuthorizationCode},
	)
	testContext.WithUser()
	testContext.WithUserSession()

	// Call AuthorizeClient Endpoint
	queryParams := url.Values{}
	queryParams.Add(common.ClientID, testClientID)
	queryParams.Add(common.RedirectURI, testRedirectURI)
	queryParams.Add(common.Scope, testScope)
	queryParams.Add(common.Approved, testConsentApproved)

	sessionCookie := testContext.GetSessionCookie()
	headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
	endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

	rr := testContext.SendHTTPRequest(
		http.MethodGet,
		endpoint,
		nil, headers,
	)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestAuthorizationHandler_TokenExchange(t *testing.T) {
	t.Run("Valid Token Request - Success", func(t *testing.T) {
		// Set up the test context
		testContext := NewVigiloTestContext(t)
		testContext.WithUser()
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)
		testContext.WithUserSession()
		defer testContext.TearDown()

		// Simulate the authorization flow
		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		queryParams.Add(common.Scope, testScope)
		queryParams.Add(common.Approved, "true")

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
		authEndpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

		authResponse := testContext.SendHTTPRequest(http.MethodGet, authEndpoint, nil, headers)
		assert.Equal(t, http.StatusFound, authResponse.Code)

		// Extract the authorization code from the redirect URL
		locationHeader := authResponse.Header().Get("Location")
		assert.NotEmpty(t, locationHeader)

		redirectURL, err := url.Parse(locationHeader)
		assert.NoError(t, err)

		authzCode := redirectURL.Query().Get("code")
		assert.NotEmpty(t, authzCode)

		// Prepare the token request
		tokenRequest := &token.TokenRequest{
			AuthorizationCode: authzCode,
			RedirectURI:       testRedirectURI,
			State:             testContext.GetStateFromSession(),
		}

		requestBody, err := json.Marshal(tokenRequest)
		assert.NoError(t, err)

		// Send the token exchange request
		tokenEndpoint := web.OAuthEndpoints.TokenExchange
		tokenResponse := testContext.SendHTTPRequest(http.MethodPost, tokenEndpoint, bytes.NewReader(requestBody), headers)

		// Assert the response
		assert.Equal(t, http.StatusOK, tokenResponse.Code)

		var response token.TokenResponse
		err = json.Unmarshal(tokenResponse.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.NotEmpty(t, response.AccessToken)
		assert.NotEmpty(t, response.RefreshToken)
		assert.Equal(t, "Bearer", response.TokenType)
		assert.Equal(t, testScope, response.Scope)
	})

	t.Run("Missing or Invalid JSON in Request Body", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.TokenExchange, bytes.NewReader([]byte("invalid-json")), nil)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		testContext.AssertErrorResponse(rr, errors.ErrCodeBadRequest, "failed to decode request body")
	})

	t.Run("Invalid Token Request Validation", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		tokenRequest := &token.TokenRequest{
			AuthorizationCode: "",
			RedirectURI:       "",
			State:             "",
		}

		requestBody, err := json.Marshal(tokenRequest)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.TokenExchange, bytes.NewReader(requestBody), nil)

		assert.Equal(t, http.StatusForbidden, rr.Code)
		testContext.AssertErrorResponse(rr, errors.ErrCodeInvalidGrant, "failed to validate request")
	})

	t.Run("State Mismatch", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithUser()
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)
		testContext.WithUserSession()
		defer testContext.TearDown()

		tokenRequest := &token.TokenRequest{
			AuthorizationCode: "valid-auth-code",
			RedirectURI:       testRedirectURI,
			State:             "invalid-state",
			ClientID:          testClientID,
			ClientSecret:      testClientSecret,
			GrantType:         client.AuthorizationCode,
		}

		requestBody, err := json.Marshal(tokenRequest)
		assert.NoError(t, err)

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}

		rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.TokenExchange, bytes.NewReader(requestBody), headers)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		testContext.AssertErrorResponse(rr, errors.ErrCodeInvalidRequest, "state mismatch between session and request")
	})
}
