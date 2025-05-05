package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

func TestAuthorizationHandler_AuthorizeClient_Success(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	testContext.WithClient(
		client.Confidential,
		[]string{constants.ClientManageScope, constants.UserManageScope},
		[]string{constants.AuthorizationCodeGrantType},
	)
	testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})
	testContext.WithUserSession()
	testContext.WithUserConsent()

	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, testClientID)
	queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
	queryParams.Add(constants.ScopeReqField, testScope)
	queryParams.Add(constants.ResponseTypeReqField, constants.CodeResponseType)
	queryParams.Add(constants.ConsentApprovedURLValue, fmt.Sprintf("%v", testConsentApproved))

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

func TestAuthorizationHandler_AuthorizeClient_MissingResponseTypeInRequest_ReturnsError(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	testContext.WithClient(
		client.Confidential,
		[]string{constants.ClientManageScope, constants.UserManageScope},
		[]string{constants.AuthorizationCodeGrantType},
	)
	testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})
	testContext.WithUserSession()
	testContext.WithUserConsent()

	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, testClientID)
	queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
	queryParams.Add(constants.ScopeReqField, testScope)
	queryParams.Add(constants.ConsentApprovedURLValue, fmt.Sprintf("%v", testConsentApproved))

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

func TestAuthorizationHandler_AuthorizeClient_NewLoginRequiredError_IsReturned(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	testContext.WithClient(
		client.Confidential,
		[]string{constants.ClientManageScope, constants.UserManageScope},
		[]string{constants.AuthorizationCodeGrantType},
	)

	testContext.WithUserConsent()

	// Call AuthorizeClient Endpoint
	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, testClientID)
	queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
	queryParams.Add(constants.ScopeReqField, testScope)
	queryParams.Add(constants.ConsentApprovedURLValue, fmt.Sprintf("%v", testConsentApproved))

	endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()
	rr := testContext.SendHTTPRequest(
		http.MethodGet,
		endpoint,
		nil, nil,
	)

	fmt.Println("BODY:", rr.Body)
	assert.Equal(t, http.StatusFound, rr.Code)
}

func TestAuthorizationHandler_AuthorizeClient_ConsentNotApproved(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	testContext.WithClient(
		client.Confidential,
		[]string{constants.ClientManageScope, constants.UserManageScope},
		[]string{constants.AuthorizationCodeGrantType},
	)

	testContext.WithUserSession()
	testContext.WithUserConsent()

	// Call AuthorizeClient Endpoint
	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, testClientID)
	queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
	queryParams.Add(constants.ScopeReqField, testScope)
	queryParams.Add(constants.ResponseTypeReqField, constants.CodeResponseType)
	queryParams.Add(constants.ConsentApprovedURLValue, "false")

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

func TestAuthorizationHandler_AuthorizeClient_ErrorIsReturnedCheckingUserConsent(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	testContext.WithClient(
		client.Confidential,
		[]string{constants.ClientManageScope, constants.UserManageScope},
		[]string{constants.AuthorizationCodeGrantType},
	)

	testContext.WithUserSession()

	// Call AuthorizeClient Endpoint
	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, testClientID)
	queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
	queryParams.Add(constants.ScopeReqField, testScope)
	queryParams.Add(constants.ResponseTypeReqField, constants.CodeResponseType)
	queryParams.Add(constants.ConsentApprovedURLValue, testConsentApproved)

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
				[]string{constants.ClientManageScope},
				[]string{constants.AuthorizationCodeGrantType},
			)

			testContext.WithUserSession()
			testContext.WithUserConsent()

			queryParams := url.Values{}
			queryParams.Add(constants.ClientIDReqField, testClientID)
			queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
			queryParams.Add(constants.ScopeReqField, constants.ClientManageScope)
			queryParams.Add(constants.ResponseTypeReqField, constants.CodeResponseType)
			queryParams.Add(constants.ConsentApprovedURLValue, fmt.Sprintf("%v", testConsentApproved))
			queryParams.Add(constants.CodeChallengeReqField, testContext.SH256CodeChallenge)
			queryParams.Add(constants.CodeChallengeMethodReqField, test.codeChallengeMethod)

			sessionCookie := testContext.GetSessionCookie()
			headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
			endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

			rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)
			assert.Equal(t, http.StatusFound, rr.Code)

			testContext.TearDown()
		}
	})

	t.Run("Error is returned when the code challenge is not provided", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Public,
			[]string{constants.ClientManageScope},
			[]string{constants.AuthorizationCodeGrantType},
		)

		testContext.WithUserSession()
		testContext.WithUserConsent()

		queryParams := testContext.CreateAuthorizationCodeRequestQueryParams("", "")
		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}
		endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)

		testContext.AssertErrorResponse(rr, errors.ErrCodeInvalidRequest, "failed to authorize client", "code_challenge is required for PKCE")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Error is returned when the code challenge method is unsupported", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Public,
			[]string{constants.ClientManageScope},
			[]string{constants.AuthorizationCodeGrantType},
		)

		testContext.WithUserSession()
		testContext.WithUserConsent()

		queryParams := url.Values{}
		queryParams.Add(constants.ClientIDReqField, testClientID)
		queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
		queryParams.Add(constants.ScopeReqField, constants.ClientManageScope)
		queryParams.Add(constants.ResponseTypeReqField, constants.CodeResponseType)
		queryParams.Add(constants.ConsentApprovedURLValue, fmt.Sprintf("%v", testConsentApproved))
		queryParams.Add(constants.CodeChallengeReqField, testContext.SH256CodeChallenge)
		queryParams.Add(constants.CodeChallengeMethodReqField, "unsupported")

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
				[]string{constants.ClientManageScope},
				[]string{constants.AuthorizationCodeGrantType},
			)

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
