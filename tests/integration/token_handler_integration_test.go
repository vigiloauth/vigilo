package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestTokenHandler_IssueTokens_ClientCredentialsGrant(t *testing.T) {
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
				assert.Equal(t, common.BearerAuthHeader, tokenResponse.TokenType)
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
		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidClient, "missing client identification")
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
		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidClient, "missing client identification")
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

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeUnauthorizedClient, "invalid client credentials or unauthorized grant type/scopes")
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
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestTokenHandler_IssueTokens_PasswordGrant(t *testing.T) {
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
				assert.Equal(t, common.BearerAuthHeader, tokenResponse.TokenType)
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

func TestTokenHandler_TokenExchange(t *testing.T) {
	t.Run("Valid Token Request - Success", func(t *testing.T) {
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

		authzCode := testContext.GetAuthzCode()

		formData := url.Values{}
		formData.Add(common.AuthzCode, authzCode)
		formData.Add(common.RedirectURI, testRedirectURI)
		formData.Add(common.State, testContext.State)
		formData.Add(common.GrantType, client.AuthorizationCode)

		headers := map[string]string{
			"Cookie":        testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Basic " + encodeClientCredentials(testClientID, testClientSecret),
		}
		rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)

		assert.Equal(t, http.StatusOK, rr.Code, "Expected a successful token exchange")
	})

	t.Run("State Mismatch", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithUser()
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage, client.UserManage},
			[]string{client.AuthorizationCode},
		)
		testContext.WithUserSession()

		formData := url.Values{}
		formData.Add(common.AuthzCode, "valid-code")
		formData.Add(common.RedirectURI, testRedirectURI)
		formData.Add(common.State, "invalid-state")
		formData.Add(common.GrantType, client.AuthorizationCode)

		headers := map[string]string{
			"Cookie":        testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Basic " + encodeClientCredentials(testClientID, testClientSecret),
		}
		rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidRequest, "state mismatch between session and request")
	})
}

func TestTokenHandler_TokenExchange_UsingPKCE(t *testing.T) {
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
			headers := map[string]string{
				"Cookie":       testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
				"Content-Type": "application/x-www-form-urlencoded",
			}

			formData := url.Values{}
			formData.Add(common.AuthzCode, authorizationCode)
			formData.Add(common.RedirectURI, testRedirectURI)
			formData.Add(common.State, testContext.State)
			formData.Add(common.GrantType, client.PKCE)
			formData.Add(common.CodeVerifier, test.codeVerifier)

			if test.clientType == client.Confidential {
				headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
			} else {
				formData.Add(common.ClientID, testClientID)
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
			headers := map[string]string{
				"Cookie":       testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
				"Content-Type": "application/x-www-form-urlencoded",
			}

			formData := url.Values{}
			formData.Add(common.AuthzCode, authorizationCode)
			formData.Add(common.RedirectURI, testRedirectURI)
			formData.Add(common.State, testContext.State)
			formData.Add(common.GrantType, client.PKCE)
			formData.Add(common.CodeVerifier, test.codeVerifier)

			if test.clientType == client.Confidential {
				headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
			} else {
				formData.Add(common.ClientID, testClientID)
			}

			rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			testContext.TearDown()
		}
	})
}

func TestTokenHandler_RefreshAccessTokenRequest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name       string
			clientType string
		}{
			{
				name:       "Success when the client is confidential",
				clientType: client.Confidential,
			},
			{
				name:       "Success when the client is public",
				clientType: client.Public,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []string{client.ClientManage}, []string{client.RefreshToken})
				testContext.WithJWTToken(testClientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())

				formData := url.Values{}
				formData.Add(common.GrantType, client.RefreshToken)
				formData.Add(common.Scope, client.ClientManage)
				formData.Add(common.RefreshToken, testContext.JWTToken)

				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if test.clientType == client.Confidential {
					headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
				} else {
					formData.Add(common.ClientID, testClientID)
				}

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
				assert.Equal(t, common.BearerAuthHeader, tokenResponse.TokenType)
				assert.Equal(t, 1800, tokenResponse.ExpiresIn)
			})
		}
	})

	t.Run("Invalid request error is returned for missing parameters", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(client.Public, []string{client.ClientManage}, []string{client.RefreshToken})
		testContext.WithJWTToken(testClientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())

		formData := url.Values{}
		formData.Add(common.ClientID, testClientID)
		formData.Add(common.RefreshToken, testContext.JWTToken)

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Invalid request error is returned for an unsupported grant type", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(client.Public, []string{client.ClientManage}, []string{client.RefreshToken})
		testContext.WithJWTToken(testClientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())

		formData := url.Values{}
		formData.Add(common.ClientID, testClientID)
		formData.Add(common.RefreshToken, testContext.JWTToken)
		formData.Add(common.Scope, client.ClientManage)
		formData.Add(common.GrantType, "invalid-grant-type")

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Invalid grant error is returned when the refresh token is invalid", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Public, []string{client.ClientManage}, []string{client.RefreshToken})

		formData := url.Values{}
		formData.Add(common.GrantType, client.RefreshToken)
		formData.Add(common.Scope, client.ClientManage)
		formData.Add(common.RefreshToken, "invalid-token")
		formData.Add(common.ClientID, testClientID)

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Invalid grant error is returned when the refresh token is expired", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Public, []string{client.ClientManage}, []string{client.RefreshToken})
		testContext.WithExpiredToken()

		formData := url.Values{}
		formData.Add(common.GrantType, client.RefreshToken)
		formData.Add(common.Scope, client.ClientManage)
		formData.Add(common.RefreshToken, testContext.JWTToken)
		formData.Add(common.ClientID, testClientID)

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Invalid grant error is returned when the refresh token is blacklisted", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Public, []string{client.ClientManage}, []string{client.RefreshToken})
		testContext.WithBlacklistedToken(testClientID)

		formData := url.Values{}
		formData.Add(common.GrantType, client.RefreshToken)
		formData.Add(common.Scope, client.ClientManage)
		formData.Add(common.RefreshToken, testContext.JWTToken)
		formData.Add(common.ClientID, testClientID)

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Unauthorized client is returned when the client does not have the 'refresh_token' grant type", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Public, []string{client.ClientManage}, []string{client.AuthorizationCode})
		testContext.WithJWTToken(testClientID, time.Duration(5)*time.Minute)

		formData := url.Values{}
		formData.Add(common.GrantType, client.RefreshToken)
		formData.Add(common.Scope, client.ClientManage)
		formData.Add(common.RefreshToken, testContext.JWTToken)
		formData.Add(common.ClientID, testClientID)

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Invalid scope error is returned when the client does not have the required scope(s)", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Public, []string{client.ClientRead}, []string{client.RefreshToken})
		testContext.WithJWTToken(testClientID, time.Duration(5)*time.Minute)

		formData := url.Values{}
		formData.Add(common.GrantType, client.RefreshToken)
		formData.Add(common.Scope, client.ClientManage)
		formData.Add(common.RefreshToken, testContext.JWTToken)
		formData.Add(common.ClientID, testClientID)

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestTokenHandler_IntrospectToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name       string
			clientType string
		}{
			{
				name:       "Successful response for confidential clients",
				clientType: client.Confidential,
			},
			{
				name:       "Successful response for public clients",
				clientType: client.Public,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []string{client.TokenIntrospect}, []string{client.PKCE})
				testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)

				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if test.clientType == client.Confidential {
					headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
				} else {
					headers["Authorization"] = "Bearer " + testContext.JWTToken
				}

				formValue := url.Values{}
				formValue.Add(common.Token, testContext.JWTToken)
				rr := testContext.SendHTTPRequest(
					http.MethodPost,
					web.OAuthEndpoints.IntrospectToken,
					strings.NewReader(formValue.Encode()),
					headers,
				)

				assert.Equal(t, http.StatusOK, rr.Code)
			})
		}
	})

	t.Run("Invalid client is returned for invalid client credentials", func(t *testing.T) {
		tests := []struct {
			name           string
			clientType     string
			headers        map[string]string
			expectedStatus int
		}{
			{
				name:           "Invalid client error is returned for confidential client with an invalid client ID",
				clientType:     client.Confidential,
				expectedStatus: http.StatusUnauthorized,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": common.BasicAuthHeader + encodeClientCredentials("invalidID", testClientSecret),
				},
			},
			{
				name:           "Invalid client error is returned for confidential client with an invalid client secret",
				expectedStatus: http.StatusUnauthorized,
				clientType:     client.Confidential,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": common.BasicAuthHeader + encodeClientCredentials(testClientID, "invalidSecret"),
				},
			},
			{
				name:           "Invalid client error is returned for public clients",
				expectedStatus: http.StatusBadRequest,
				clientType:     client.Public,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": common.BearerAuthHeader + "invalid-token",
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []string{client.TokenIntrospect}, []string{client.ClientCredentials})
				testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)

				formValue := url.Values{}
				formValue.Add(common.Token, testContext.JWTToken)

				rr := testContext.SendHTTPRequest(
					http.MethodPost,
					web.OAuthEndpoints.IntrospectToken,
					strings.NewReader(formValue.Encode()),
					test.headers,
				)

				assert.Equal(t, test.expectedStatus, rr.Code)
			})
		}
	})

	t.Run("Active is set to false when the requested token is expired", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Confidential, []string{client.TokenIntrospect}, []string{client.ClientCredentials})
		testContext.WithExpiredToken()

		formValue := url.Values{}
		formValue.Add(common.Token, testContext.JWTToken)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": common.BasicAuthHeader + encodeClientCredentials(testClientID, testClientSecret),
		}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.IntrospectToken,
			strings.NewReader(formValue.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusOK, rr.Code)

		var tokenResponse token.TokenIntrospectionResponse
		err := json.NewDecoder(rr.Body).Decode(&tokenResponse)
		assert.NoError(t, err)

		assert.False(t, tokenResponse.Active)
	})

	t.Run("Active is set to false when the requested token is blacklisted", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Confidential, []string{client.TokenIntrospect}, []string{client.ClientCredentials})
		testContext.WithBlacklistedToken(testClientID)

		formValue := url.Values{}
		formValue.Add(common.Token, testContext.JWTToken)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": common.BasicAuthHeader + encodeClientCredentials(testClientID, testClientSecret),
		}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.IntrospectToken,
			strings.NewReader(formValue.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusOK, rr.Code)

		var tokenResponse token.TokenIntrospectionResponse
		err := json.NewDecoder(rr.Body).Decode(&tokenResponse)
		assert.NoError(t, err)

		assert.False(t, tokenResponse.Active)
	})

	t.Run("Error is returned when the client does not have the necessary scopes", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Confidential, []string{client.ClientRead}, []string{client.ClientCredentials})
		testContext.WithBlacklistedToken(testClientID)

		formValue := url.Values{}
		formValue.Add(common.Token, testContext.JWTToken)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": common.BasicAuthHeader + encodeClientCredentials(testClientID, testClientSecret),
		}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.IntrospectToken,
			strings.NewReader(formValue.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestTokenHandler_RevokeToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name       string
			clientType string
		}{
			{
				name:       "Successful response for confidential clients",
				clientType: client.Confidential,
			},
			{
				name:       "Successful response for public clients",
				clientType: client.Public,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []string{client.TokenRevoke}, []string{client.PKCE})
				testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)

				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if test.clientType == client.Confidential {
					headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
				} else {
					headers["Authorization"] = "Bearer " + testContext.JWTToken
				}

				formValue := url.Values{}
				formValue.Add(common.Token, testContext.JWTToken)
				rr := testContext.SendHTTPRequest(
					http.MethodPost,
					web.OAuthEndpoints.RevokeToken,
					strings.NewReader(formValue.Encode()),
					headers,
				)

				assert.Equal(t, http.StatusOK, rr.Code)
			})
		}
	})

	t.Run("Error is returned for invalid authentication", func(t *testing.T) {
		tests := []struct {
			name           string
			clientType     string
			headers        map[string]string
			expectedStatus int
		}{
			{
				name:           "Invalid client error is returned for confidential client with an invalid client ID",
				clientType:     client.Confidential,
				expectedStatus: http.StatusUnauthorized,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": common.BasicAuthHeader + encodeClientCredentials("invalidID", testClientSecret),
				},
			},
			{
				name:           "Invalid client error is returned for confidential client with an invalid client secret",
				expectedStatus: http.StatusUnauthorized,
				clientType:     client.Confidential,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": common.BasicAuthHeader + encodeClientCredentials(testClientID, "invalidSecret"),
				},
			},
			{
				name:           "Invalid client error is returned for public clients",
				expectedStatus: http.StatusBadRequest,
				clientType:     client.Public,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": common.BearerAuthHeader + "invalid-token",
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []string{client.TokenIntrospect}, []string{client.ClientCredentials})
				testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)

				formValue := url.Values{}
				formValue.Add(common.Token, testContext.JWTToken)

				rr := testContext.SendHTTPRequest(
					http.MethodPost,
					web.OAuthEndpoints.RevokeToken,
					strings.NewReader(formValue.Encode()),
					test.headers,
				)

				assert.Equal(t, test.expectedStatus, rr.Code)
			})
		}
	})

	t.Run("Error is returned when the client does not have the required scopes", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Confidential, []string{client.ClientRead}, []string{client.ClientCredentials})
		testContext.WithBlacklistedToken(testClientID)

		formValue := url.Values{}
		formValue.Add(common.Token, testContext.JWTToken)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": common.BasicAuthHeader + encodeClientCredentials(testClientID, testClientSecret),
		}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.RevokeToken,
			strings.NewReader(formValue.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
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
