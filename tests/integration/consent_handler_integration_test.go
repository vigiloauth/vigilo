package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	consent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

func TestConsentHandler_UserConsent(t *testing.T) {
	t.Run("GET Request - returns client and scope information", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUserSession()
		testContext.WithClient(
			types.ConfidentialClient,
			[]types.Scope{types.OpenIDScope},
			[]string{constants.AuthorizationCodeGrantType},
		)

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}

		queryParams := url.Values{}
		queryParams.Add(constants.ClientIDReqField, testClientID)
		queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
		queryParams.Add(constants.ScopeReqField, testScope)
		endpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("POST Request - Success", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUserSession()
		testContext.WithClient(
			types.ConfidentialClient,
			[]types.Scope{types.OpenIDScope},
			[]string{constants.AuthorizationCodeGrantType},
		)

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}

		queryParams := url.Values{}
		queryParams.Add(constants.ClientIDReqField, testClientID)
		queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
		queryParams.Add(constants.ScopeReqField, testScope)
		postEndpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()

		userConsentRequest := &consent.UserConsentRequest{
			Approved: true,
			Scopes:   []types.Scope{types.OpenIDScope},
		}

		requestBody, err := json.Marshal(userConsentRequest)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(http.MethodPost, postEndpoint, bytes.NewReader(requestBody), headers)

		assert.Equal(t, http.StatusOK, rr.Code)
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

				testContext.WithUserSession()
				testContext.WithClient(
					types.ConfidentialClient,
					[]types.Scope{types.OpenIDScope},
					[]string{constants.AuthorizationCodeGrantType},
				)

				rr := testContext.SendHTTPRequest(http.MethodGet, test.endpoint, nil, nil)
				assert.Equal(t, http.StatusBadRequest, rr.Code)
				testContext.AssertErrorResponseDescription(rr, errors.ErrCodeBadRequest, "missing required parameters")
			})
		}
	})

	t.Run("Post Request - Client missing required scopes", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUserSession()
		testContext.WithClient(
			types.ConfidentialClient,
			[]types.Scope{types.OpenIDScope},
			[]string{constants.AuthorizationCodeGrantType},
		)

		sessionCookie := testContext.GetSessionCookie()
		headers := map[string]string{"Cookie": sessionCookie.Name + "=" + sessionCookie.Value}

		// Send GET request to fetch state
		queryParams := url.Values{}
		queryParams.Add(constants.ClientIDReqField, testClientID)
		queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
		queryParams.Add(constants.ScopeReqField, testScope)
		getEndpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()

		rr := testContext.SendHTTPRequest(http.MethodGet, getEndpoint, nil, headers)
		assert.Equal(t, http.StatusOK, rr.Code)
	})

}
