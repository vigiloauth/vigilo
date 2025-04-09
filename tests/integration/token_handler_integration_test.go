package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestAuthHandler_IssueTokens_ClientCredentialsGrant(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name         string
			clientType   string
			clientSecret string
		}{
			{
				name:         "Success when client is public",
				clientType:   client.Public,
				clientSecret: "",
			},
			{
				name:         "Success when client is confidential",
				clientType:   client.Confidential,
				clientSecret: testClientSecret,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(
					test.clientType,
					[]string{client.ClientManage},
					[]string{client.ClientCredentials},
				)

				formData := url.Values{}
				formData.Add(common.GrantType, client.ClientCredentials)
				formData.Add(common.Scope, client.ClientManage)

				headers := generateHeaderWithCredentials(testClientID, test.clientSecret)

				rr := testContext.SendHTTPRequest(
					http.MethodPost,
					web.OAuthEndpoints.Token,
					strings.NewReader(formData.Encode()),
					headers,
				)

				assert.Equal(t, http.StatusOK, rr.Code)
				assert.NotNil(t, rr.Body)

				var tokenResponse token.TokenResponse
				err := json.NewDecoder(rr.Body).Decode(&tokenResponse)
				assert.NoError(t, err)

				assert.NotNil(t, tokenResponse.AccessToken)
				assert.Equal(t, common.Bearer, tokenResponse.TokenType)
				assert.Equal(t, 1800, tokenResponse.ExpiresIn)
			})
		}
	})

	t.Run("Error is returned when the client ID is invalid", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]string{client.ClientCredentials},
		)

		formData := url.Values{}
		formData.Add(common.GrantType, client.ClientCredentials)
		formData.Add(common.Scope, client.ClientManage)

		headers := generateHeaderWithCredentials("non-existing-id", testClientSecret)
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		testContext.AssertErrorResponseDescription(
			rr, errors.ErrCodeInvalidClient,
			"invalid client credentials or unauthorized grant type/scopes",
		)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Error is returned when authorization header is missing", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		formData := url.Values{}
		formData.Add(common.GrantType, client.ClientCredentials)
		formData.Add(common.Scope, client.ClientManage)

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidClient, "invalid authorization header")
	})

	t.Run("Error is returned when authorization header is invalid", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Basic invalid_credentials",
		}

		formData := url.Values{}
		formData.Add(common.GrantType, client.ClientCredentials)
		formData.Add(common.Scope, client.ClientManage)

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidClient, "invalid authorization header")
	})

	t.Run("Error is returned when client secrets do not match", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]string{client.ClientCredentials},
		)

		formData := url.Values{}
		formData.Add(common.GrantType, client.ClientCredentials)
		formData.Add(common.Scope, client.ClientManage)
		headers := generateHeaderWithCredentials(testClientID, "invalid-secret")

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidClient, "invalid client credentials or unauthorized grant type/scopes")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Error is returned when client is missing required grant types", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]string{client.AuthorizationCode}, // unsupported grant type
		)

		formData := url.Values{}
		formData.Add(common.GrantType, client.ClientCredentials)
		formData.Add(common.Scope, client.ClientManage)

		headers := generateHeaderWithCredentials(testClientID, testClientSecret)
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidGrant, "invalid client credentials or unauthorized grant type/scopes")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Error is returned when client is missing required scope", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientRead},
			[]string{client.ClientCredentials},
		)

		formData := url.Values{}
		formData.Add(common.GrantType, client.ClientCredentials)
		formData.Add(common.Scope, client.ClientDelete)

		headers := generateHeaderWithCredentials(testClientID, testClientSecret)
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInsufficientScope, "invalid client credentials or unauthorized grant type/scopes")
		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}

func TestAuthenticationService_IssueTokens_PasswordGrant(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name         string
			clientType   string
			clientSecret string
		}{
			{
				name:         "Success when client is confidential",
				clientType:   client.Confidential,
				clientSecret: testClientSecret,
			},
			{
				name:         "Success when client is public",
				clientType:   client.Public,
				clientSecret: "",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []string{client.UserManage}, []string{client.PasswordGrant})
				testContext.WithUser()

				formData := url.Values{}
				formData.Add(common.GrantType, client.PasswordGrant)
				formData.Add(common.Scope, client.UserManage)
				formData.Add(common.Username, testUsername)
				formData.Add(common.Password, testPassword1)

				headers := generateHeaderWithCredentials(testClientID, test.clientSecret)
				rr := testContext.SendHTTPRequest(
					http.MethodPost,
					web.OAuthEndpoints.Token,
					strings.NewReader(formData.Encode()),
					headers,
				)

				assert.Equal(t, http.StatusOK, rr.Code)
				assert.NotNil(t, rr.Body)

				var tokenResponse token.TokenResponse
				err := json.NewDecoder(rr.Body).Decode(&tokenResponse)
				assert.NoError(t, err)

				assert.NotNil(t, tokenResponse.AccessToken)
				assert.Equal(t, common.Bearer, tokenResponse.TokenType)
				assert.Equal(t, 1800, tokenResponse.ExpiresIn)
			})
		}
	})

	t.Run("Error is returned when client authentication fails", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Confidential, []string{client.UserManage}, []string{client.PasswordGrant})
		testContext.WithUser()

		formData := url.Values{}
		formData.Add(common.GrantType, client.PasswordGrant)
		formData.Add(common.Scope, client.ClientManage)
		formData.Add(common.Username, testUsername)
		formData.Add(common.Password, testPassword1)

		headers := generateHeaderWithCredentials("non-existing-id", testClientSecret)
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Error is returned when user authentication fails", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Confidential, []string{client.UserManage}, []string{client.PasswordGrant})
		testContext.WithUser()

		formData := url.Values{}
		formData.Add(common.GrantType, client.PasswordGrant)
		formData.Add(common.Scope, client.UserManage)
		formData.Add(common.Username, testUsername)
		formData.Add(common.Password, "invalid-password")

		headers := generateHeaderWithCredentials(testClientID, testClientSecret)
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Error is returned when client secrets do not match", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Confidential, []string{client.UserManage}, []string{client.PasswordGrant})
		testContext.WithUser()

		formData := url.Values{}
		formData.Add(common.GrantType, client.PasswordGrant)
		formData.Add(common.Scope, client.UserManage)
		formData.Add(common.Username, testUsername)
		formData.Add(common.Password, testPassword1)

		headers := generateHeaderWithCredentials(testClientID, "invalid-secret")
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
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

func generateHeaderWithCredentials(id, secret string) map[string]string {
	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic " + encodeClientCredentials(id, secret),
	}

	return headers
}

func encodeClientCredentials(clientID, clientSecret string) string {
	return base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
}
