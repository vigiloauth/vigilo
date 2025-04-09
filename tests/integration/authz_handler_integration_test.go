package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestAuthorizationHandler_AuthorizeClient_Success(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage, client.UserManage},
		[]string{client.AuthorizationCode},
	)
	testContext.WithUser()
	testContext.WithUserSession()
	testContext.WithUserConsent()

	queryParams := url.Values{}
	queryParams.Add(common.ClientID, testClientID)
	queryParams.Add(common.RedirectURI, testRedirectURI)
	queryParams.Add(common.Scope, testScope)
	queryParams.Add(common.ResponseType, client.CodeResponseType)
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
	defer testContext.TearDown()

	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage, client.UserManage},
		[]string{client.AuthorizationCode, client.PKCE},
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
	defer testContext.TearDown()

	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage, client.UserManage},
		[]string{client.AuthorizationCode, client.PKCE},
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
	defer testContext.TearDown()

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
	queryParams.Add(common.ResponseType, client.CodeResponseType)
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
	defer testContext.TearDown()

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
	queryParams.Add(common.ResponseType, client.CodeResponseType)
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

func TestAuthorizationHandler_AuthorizeClient_UsingPKCE(t *testing.T) {
	t.Run("Success when client is using PKCE", func(t *testing.T) {
		tests := []struct {
			name                string
			codeChallengeMethod string
			clientType          string
		}{
			{
				name:                "Confidential using SHA-256 code challenge method",
				codeChallengeMethod: client.S256,
				clientType:          client.Confidential,
			},
			{
				name:                "Confidential using plain code challenge method",
				codeChallengeMethod: client.Plain,
				clientType:          client.Confidential,
			},
			{
				name:                "Public client using SHA-256 code challenge method",
				codeChallengeMethod: client.S256,
				clientType:          client.Public,
			},
			{
				name:                "Public client using plain code challenge method",
				codeChallengeMethod: client.Plain,
				clientType:          client.Public,
			},
		}

		for _, test := range tests {
			testContext := NewVigiloTestContext(t)
			testContext.WithClient(
				test.clientType,
				[]string{client.ClientManage},
				[]string{client.AuthorizationCode, client.PKCE},
			)
			testContext.WithUser()
			testContext.WithUserSession()
			testContext.WithUserConsent()

			queryParams := url.Values{}
			queryParams.Add(common.ClientID, testClientID)
			queryParams.Add(common.RedirectURI, testRedirectURI)
			queryParams.Add(common.Scope, client.ClientManage)
			queryParams.Add(common.ResponseType, client.CodeResponseType)
			queryParams.Add(common.Approved, fmt.Sprintf("%v", testConsentApproved))
			queryParams.Add(common.CodeChallenge, testContext.SH256CodeChallenge)
			queryParams.Add(common.CodeChallengeMethod, test.codeChallengeMethod)

			sessionCookie := testContext.GetSessionCookie()
			headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
			endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

			rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)
			assert.Equal(t, http.StatusFound, rr.Code)

			testContext.TearDown()
		}
	})

	t.Run("Error is returned when public client does not have PKCE grant type", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Public,
			[]string{client.ClientManage},
			[]string{client.AuthorizationCode},
		)
		testContext.WithUser()
		testContext.WithUserSession()
		testContext.WithUserConsent()

		queryParams := testContext.CreateAuthorizationCodeRequestQueryParams(testContext.SH256CodeChallenge, client.S256)
		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
		endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)

		testContext.AssertErrorResponse(rr, errors.ErrCodeInvalidGrant, "failed to authorize client", "public clients are required to use PKCE")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Error is returned when the code challenge is not provided", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Public,
			[]string{client.ClientManage},
			[]string{client.AuthorizationCode, client.PKCE},
		)
		testContext.WithUser()
		testContext.WithUserSession()
		testContext.WithUserConsent()

		queryParams := testContext.CreateAuthorizationCodeRequestQueryParams("", "")
		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
		endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)

		testContext.AssertErrorResponse(rr, errors.ErrCodeInvalidRequest, "failed to authorize client", "'code_challenge' is required for PKCE")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Error is returned when the code challenge method is unsupported", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Public,
			[]string{client.ClientManage},
			[]string{client.AuthorizationCode, client.PKCE},
		)
		testContext.WithUser()
		testContext.WithUserSession()
		testContext.WithUserConsent()

		queryParams := url.Values{}
		queryParams.Add(common.ClientID, testClientID)
		queryParams.Add(common.RedirectURI, testRedirectURI)
		queryParams.Add(common.Scope, client.ClientManage)
		queryParams.Add(common.ResponseType, client.CodeResponseType)
		queryParams.Add(common.Approved, fmt.Sprintf("%v", testConsentApproved))
		queryParams.Add(common.CodeChallenge, testContext.SH256CodeChallenge)
		queryParams.Add(common.CodeChallengeMethod, "unsupported")

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
		endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)

		testContext.AssertErrorResponse(
			rr, errors.ErrCodeInvalidRequest,
			"failed to authorize client", "invalid code challenge method: 'unsupported'. Valid methods are 'plain' and 'SHA-256'",
		)
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Error is returned when the code challenge is invalid", func(t *testing.T) {
		tests := []struct {
			name                   string
			codeChallenge          string
			expectedErrCode        string
			expectedErrDescription string
			expectedErrDetails     string
		}{
			{
				name:                   "Code challenge doesn't meet length requirements",
				codeChallenge:          "too-short",
				expectedErrCode:        errors.ErrCodeInvalidRequest,
				expectedErrDescription: "failed to authorize client",
				expectedErrDetails:     "invalid code challenge length (9): must be between 43 and 128 characters",
			},
			{
				name:                   "Code challenge exceeds maximum length",
				codeChallenge:          "aZ9xJdLqP7vNwB2CmKRoGf5YTsU8hVXtW6M1yEpQbA3gD4FcHZJLnPrVkO0SmuIzXWeTYoNq58KRC1Mv7LJ9QFhD6B2aG3pUWMtYsXVo0ZJNfzxPdLqKmTB8O5CyA1rGV7H",
				expectedErrCode:        errors.ErrCodeInvalidRequest,
				expectedErrDescription: "failed to authorize client",
				expectedErrDetails:     "invalid code challenge length (131): must be between 43 and 128 characters",
			},
			{
				name:                   "Code challenge contains invalid characters",
				codeChallenge:          "abcDEF123._~-@#$%^&*()+=[]{}|:;<>,?/xyzXYZ456789",
				expectedErrCode:        errors.ErrCodeInvalidRequest,
				expectedErrDescription: "failed to authorize client",
				expectedErrDetails:     "invalid characters: only A-Z, a-z, 0-9, '-', and '_' are allowed (Base64 URL encoding)",
			},
		}

		for _, test := range tests {
			testContext := NewVigiloTestContext(t)
			testContext.WithClient(
				client.Public,
				[]string{client.ClientManage},
				[]string{client.AuthorizationCode, client.PKCE},
			)
			testContext.WithUser()
			testContext.WithUserSession()
			testContext.WithUserConsent()

			queryParams := testContext.CreateAuthorizationCodeRequestQueryParams(test.codeChallenge, client.S256)
			sessionCookie := testContext.GetSessionCookie()
			headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
			endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

			rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)

			testContext.AssertErrorResponse(rr, test.expectedErrCode, test.expectedErrDescription, test.expectedErrDetails)
			assert.Equal(t, http.StatusBadRequest, rr.Code)

			testContext.TearDown()
		}
	})
}

func TestAuthorizationHandler_TokenExchange(t *testing.T) {
	t.Run("Valid Token Request - Success", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)
		testContext.WithUser()
		testContext.WithUserSession()
		testContext.WithUserConsent()
		defer testContext.TearDown()

		authzCode := testContext.GetAuthzCode()

		formData := url.Values{}
		formData.Add(common.AuthzCode, authzCode)
		formData.Add(common.RedirectURI, testRedirectURI)
		formData.Add(common.State, testContext.State)
		formData.Add(common.ClientID, testClientID)
		formData.Add(common.ClientSecret, testClientSecret)
		formData.Add(common.GrantType, client.AuthorizationCode)

		headers := map[string]string{
			"Cookie":       testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
			"Content-Type": "application/x-www-form-urlencoded",
		}
		rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)

		assert.Equal(t, http.StatusOK, rr.Code, "Expected a successful token exchange")
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

		formData := url.Values{}
		formData.Add(common.AuthzCode, "valid-code")
		formData.Add(common.RedirectURI, testRedirectURI)
		formData.Add(common.State, "invalid-state")
		formData.Add(common.ClientID, testClientID)
		formData.Add(common.ClientSecret, testClientSecret)
		formData.Add(common.GrantType, client.AuthorizationCode)

		headers := map[string]string{
			"Cookie":       testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
			"Content-Type": "application/x-www-form-urlencoded",
		}
		rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidRequest, "state mismatch between session and request")
	})
}

func TestAuthorizationHandler_TokenExchange_UsingPKCE(t *testing.T) {
	t.Run("Success when client is using PKCE", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		tests := []struct {
			name                string
			clientType          string
			codeChallengeMethod string
			codeChallenge       string
			codeVerifier        string
		}{
			{
				name:                "Success when confidential client uses plain method",
				clientType:          client.Confidential,
				codeChallengeMethod: client.Plain,
				codeChallenge:       testContext.PlainCodeChallenge,
				codeVerifier:        testContext.PlainCodeChallenge,
			},
			{
				name:                "Success when confidential client uses SHA-256 method",
				clientType:          client.Confidential,
				codeChallengeMethod: client.S256,
				codeChallenge:       testContext.SH256CodeChallenge,
				codeVerifier:        testClientSecret,
			},
			{
				name:                "Success when public client uses plain method",
				clientType:          client.Public,
				codeChallengeMethod: client.Plain,
				codeChallenge:       testContext.PlainCodeChallenge,
				codeVerifier:        testContext.PlainCodeChallenge,
			},
			{
				name:                "Success when public client uses SHA-256 method",
				clientType:          client.Public,
				codeChallengeMethod: client.S256,
				codeChallenge:       testContext.SH256CodeChallenge,
				codeVerifier:        testClientSecret,
			},
		}

		for _, test := range tests {
			testContext.WithClient(
				test.clientType,
				[]string{client.ClientManage},
				[]string{client.AuthorizationCode, client.PKCE},
			)
			testContext.WithUser()
			testContext.WithUserSession()
			testContext.WithUserConsent()

			authorizationCode := testContext.GetAuthzCodeWithPKCE(test.codeChallenge, test.codeChallengeMethod)

			formData := url.Values{}
			formData.Add(common.AuthzCode, authorizationCode)
			formData.Add(common.RedirectURI, testRedirectURI)
			formData.Add(common.State, testContext.State)
			formData.Add(common.ClientID, testClientID)
			formData.Add(common.GrantType, client.PKCE)
			formData.Add(common.CodeVerifier, test.codeVerifier)

			if test.clientType == client.Confidential {
				formData.Add(common.ClientSecret, testClientSecret)
			}

			headers := map[string]string{
				"Cookie":       testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
				"Content-Type": "application/x-www-form-urlencoded",
			}
			rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)

			assert.Equal(t, http.StatusOK, rr.Code)
			testContext.TearDown()
		}
	})

	t.Run("Error is returned for invalid code verifier", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		invalidCodeVerifier := "invalid-code-verifier"
		tests := []struct {
			name         string
			clientType   string
			codeVerifier string
		}{
			{
				name:         "Invalid code verifier for confidential client",
				clientType:   client.Confidential,
				codeVerifier: invalidCodeVerifier,
			},
			{
				name:         "Invalid code verifier for public client",
				clientType:   client.Public,
				codeVerifier: invalidCodeVerifier,
			},
			{
				name:         "Code verifier not provided in the request",
				clientType:   client.Confidential,
				codeVerifier: "",
			},
		}

		for _, test := range tests {
			testContext.WithClient(
				test.clientType,
				[]string{client.ClientManage},
				[]string{client.AuthorizationCode, client.PKCE},
			)
			testContext.WithUser()
			testContext.WithUserSession()
			testContext.WithUserConsent()

			authorizationCode := testContext.GetAuthzCodeWithPKCE(testContext.PlainCodeChallenge, client.Plain)

			formData := url.Values{}
			formData.Add(common.AuthzCode, authorizationCode)
			formData.Add(common.RedirectURI, testRedirectURI)
			formData.Add(common.State, testContext.State)
			formData.Add(common.ClientID, testClientID)
			formData.Add(common.GrantType, client.PKCE)
			formData.Add(common.CodeVerifier, test.codeVerifier)

			if test.clientType == client.Confidential {
				formData.Add(common.ClientSecret, testClientSecret)
			}

			headers := map[string]string{
				"Cookie":       testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
				"Content-Type": "application/x-www-form-urlencoded",
			}
			rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			testContext.TearDown()
		}
	})
}
