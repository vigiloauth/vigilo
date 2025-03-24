package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
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
	testContext.WithSession()

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
	testContext.WithSession()

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
	testContext.WithSession()
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
	testContext.WithSession()

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
