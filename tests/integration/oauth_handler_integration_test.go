package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestOauthHandler_OAuthLogin(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser()
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)

		loginRequest := users.UserLoginRequest{
			ID:       testUserID,
			Username: testUsername,
			Password: testPassword1,
		}

		requestBody, err := json.Marshal(loginRequest)
		assert.NoError(t, err)

		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		endpoint := web.OAuthEndpoints.Login + "?" + queryParams.Encode()

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
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)

		loginRequest := users.UserLoginRequest{
			ID:       testUserID,
			Username: testUsername,
			Password: testPassword1,
		}

		requestBody, err := json.Marshal(loginRequest)
		assert.NoError(t, err)

		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		endpoint := web.OAuthEndpoints.Login + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			endpoint,
			bytes.NewReader(requestBody), nil,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestOAuthHandler_UserConsent(t *testing.T) {
	t.Run("GET Request - returns client and scope information", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser()
		testContext.WithUserSession()
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}

		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		queryParams.Add(common.Scope, testScope)
		endpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("POST Request - Success", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser()
		testContext.WithUserSession()
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}

		state := testContext.GetStateFromSession()
		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		queryParams.Add(common.Scope, testScope)
		queryParams.Add(common.State, state)
		postEndpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()

		userConsentRequest := &consent.UserConsentRequest{
			Approved: true,
			Scopes:   []string{client.ClientManage, client.UserManage},
		}

		requestBody, err := json.Marshal(userConsentRequest)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(http.MethodPost, postEndpoint, bytes.NewReader(requestBody), headers)

		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("No user session present returns LoginRequiredError", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)

		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		queryParams.Add(common.Scope, testScope)

		endpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()
		rr := testContext.SendHTTPRequest(http.MethodPost, endpoint, nil, nil)

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeLoginRequired, "authentication required to continue the authorization flow")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Missing required OAuth parameters returns error", func(t *testing.T) {
		tests := []struct {
			name     string
			endpoint string
		}{
			{
				name:     "Missing clientID",
				endpoint: web.OAuthEndpoints.UserConsent + "?redirect_uri=" + testRedirectURI + "&scope=" + encodedTestScope,
			},
			{
				name:     "Missing redirectURI",
				endpoint: web.OAuthEndpoints.UserConsent + "?client_id=" + testClientID + "&scope=" + encodedTestScope,
			},
			{
				name:     "Missing scope",
				endpoint: web.OAuthEndpoints.UserConsent + "?client_id=" + testClientID + "&redirect_uri=" + testRedirectURI,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithUser()
				testContext.WithUserSession()
				testContext.WithClient(
					client.Confidential,
					[]string{client.ClientManage, client.UserManage},
					[]string{client.AuthorizationCode},
				)

				rr := testContext.SendHTTPRequest(http.MethodGet, test.endpoint, nil, nil)
				assert.Equal(t, http.StatusBadRequest, rr.Code)
				testContext.AssertErrorResponseDescription(rr, errors.ErrCodeBadRequest, "missing required OAuth parameters")
			})
		}
	})

	t.Run("Post Request - state mismatch", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithUser()
		defer testContext.TearDown()

		testContext.WithUser()
		testContext.WithUserSession()
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}

		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		queryParams.Add(common.Scope, testScope)
		queryParams.Add(common.State, "invalid-state")
		endpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()

		userConsentRequest := &consent.UserConsentRequest{
			Approved: true,
			Scopes:   []string{client.ClientManage, client.UserRead},
		}

		requestBody, err := json.Marshal(userConsentRequest)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(http.MethodPost, endpoint, bytes.NewReader(requestBody), headers)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Post Request - Client missing required scopes", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser()
		testContext.WithUserSession()
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]string{client.AuthorizationCode},
		)

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}

		// Send GET request to fetch state
		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		queryParams.Add(common.Scope, testScope)
		getEndpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(http.MethodGet, getEndpoint, nil, headers)
		assert.Equal(t, http.StatusOK, rr.Code)

		// Parse the response to extract the state
		var consentResponse consent.UserConsentResponse
		err := json.Unmarshal(rr.Body.Bytes(), &consentResponse)
		assert.NoError(t, err)
		state := consentResponse.State
		assert.NotEmpty(t, state)

		queryParams.Add(common.State, state)
		postEndpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()
		userConsentRequest := &consent.UserConsentRequest{
			Approved: true,
			Scopes:   []string{client.ClientManage, client.UserManage},
		}

		requestBody, err := json.Marshal(userConsentRequest)
		assert.NoError(t, err)

		rr = testContext.SendHTTPRequest(http.MethodPost, postEndpoint, bytes.NewReader(requestBody), headers)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Post Request - user denies consent", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser()
		testContext.WithUserSession()
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}

		// Send GET request to fetch state
		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		queryParams.Add(common.Scope, testScope)
		getEndpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(http.MethodGet, getEndpoint, nil, headers)
		assert.Equal(t, http.StatusOK, rr.Code)

		var consentResponse consent.UserConsentResponse
		err := json.Unmarshal(rr.Body.Bytes(), &consentResponse)
		assert.NoError(t, err)
		state := consentResponse.State
		assert.NotEmpty(t, state)

		queryParams.Add(common.State, state)
		postEndpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()
		userConsentRequest := &consent.UserConsentRequest{
			Approved: false,
		}

		requestBody, err := json.Marshal(userConsentRequest)
		assert.NoError(t, err)

		rr = testContext.SendHTTPRequest(http.MethodPost, postEndpoint, bytes.NewReader(requestBody), headers)
		assert.Equal(t, http.StatusOK, rr.Code)
	})
}
