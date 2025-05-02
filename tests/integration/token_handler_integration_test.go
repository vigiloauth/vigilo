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
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

func TestTokenHandler_IssueTokens_ClientCredentialsGrant(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name         string
			clientType   string
			clientSecret string
		}{
			{
				name:         "Error is successfully returned when the client is public",
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
					[]string{constants.ClientManageScope},
					[]string{constants.ClientCredentialsGrantType},
				)

				formData := url.Values{}
				formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
				formData.Add(constants.ScopeReqField, constants.ClientManageScope)

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
				assert.Equal(t, constants.BearerAuthHeader, tokenResponse.TokenType)
				assert.Equal(t, 1800, tokenResponse.ExpiresIn)
			})
		}
	})

	t.Run("Error is returned when the client ID is invalid", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			client.Confidential,
			[]string{constants.ClientManageScope},
			[]string{constants.ClientCredentialsGrantType},
		)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)

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
		formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)

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
		formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)

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
			[]string{constants.ClientManageScope},
			[]string{constants.ClientCredentialsGrantType},
		)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)
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
			[]string{constants.ClientManageScope},
			[]string{constants.AuthorizationCodeGrantType}, // unsupported grant type
		)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)

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
			[]string{constants.ClientReadScope},
			[]string{constants.ClientCredentialsGrantType},
		)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientDeleteScope)

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
				name:         "Error is successfully returned when the client is public",
				clientType:   client.Public,
				clientSecret: "",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []string{constants.UserManageScope}, []string{constants.PasswordGrantType})
				testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})

				formData := url.Values{}
				formData.Add(constants.GrantTypeReqField, constants.PasswordGrantType)
				formData.Add(constants.ScopeReqField, constants.UserManageScope)
				formData.Add(constants.UsernameReqField, testUsername)
				formData.Add(constants.PasswordReqField, testPassword1)

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
				assert.Equal(t, constants.BearerAuthHeader, tokenResponse.TokenType)
				assert.Equal(t, 1800, tokenResponse.ExpiresIn)
			})
		}
	})

	t.Run("Error is returned when client authentication fails", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(client.Confidential, []string{constants.UserManageScope}, []string{constants.PasswordGrantType})
		testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.PasswordGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)
		formData.Add(constants.UsernameReqField, testUsername)
		formData.Add(constants.PasswordReqField, testPassword1)

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

		testContext.WithClient(client.Confidential, []string{constants.UserManageScope}, []string{constants.PasswordGrantType})
		testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.PasswordGrantType)
		formData.Add(constants.ScopeReqField, constants.UserManageScope)
		formData.Add(constants.UsernameReqField, testUsername)
		formData.Add(constants.PasswordReqField, "invalid-password")

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

		testContext.WithClient(client.Confidential, []string{constants.UserManageScope}, []string{constants.PasswordGrantType})
		testContext.WithUser([]string{constants.UserManageScope}, []string{constants.AdminRole})

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.PasswordGrantType)
		formData.Add(constants.ScopeReqField, constants.UserManageScope)
		formData.Add(constants.UsernameReqField, testUsername)
		formData.Add(constants.PasswordReqField, testPassword1)

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

		testContext.WithUserSession()
		testContext.WithUserConsent()
		testContext.WithClient(
			client.Confidential,
			[]string{constants.ClientManageScope, constants.UserManageScope},
			[]string{constants.AuthorizationCodeGrantType},
		)

		authzCode := testContext.GetAuthzCode()

		formData := url.Values{}
		formData.Add(constants.CodeURLValue, authzCode)
		formData.Add(constants.RedirectURIReqField, testRedirectURI)
		formData.Add(constants.StateReqField, testContext.State)
		formData.Add(constants.GrantTypeReqField, constants.AuthorizationCodeGrantType)

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

		testContext.WithUserSession()
		testContext.WithClient(
			client.Confidential,
			[]string{constants.ClientManageScope, constants.UserManageScope},
			[]string{constants.AuthorizationCodeGrantType},
		)

		formData := url.Values{}
		formData.Add(constants.CodeURLValue, "valid-code")
		formData.Add(constants.RedirectURIReqField, testRedirectURI)
		formData.Add(constants.StateReqField, "invalid-state")
		formData.Add(constants.GrantTypeReqField, constants.AuthorizationCodeGrantType)

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
				[]string{constants.ClientManageScope},
				[]string{constants.AuthorizationCodeGrantType},
			)

			testContext.WithUser([]string{constants.ClientManageScope}, []string{constants.AdminRole})
			testContext.WithUserSession()
			testContext.WithUserConsent()

			authorizationCode := testContext.GetAuthzCodeWithPKCE(test.codeChallenge, test.codeChallengeMethod)
			headers := map[string]string{
				"Cookie":       testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
				"Content-Type": "application/x-www-form-urlencoded",
			}

			formData := url.Values{}
			formData.Add(constants.CodeURLValue, authorizationCode)
			formData.Add(constants.RedirectURIReqField, testRedirectURI)
			formData.Add(constants.StateReqField, testContext.State)
			formData.Add(constants.GrantTypeReqField, constants.AuthorizationCodeGrantType)
			formData.Add(constants.CodeVerifierReqField, test.codeVerifier)

			if test.clientType == client.Confidential {
				headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
			} else {
				formData.Add(constants.ClientIDReqField, testClientID)
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
				name:         "Invalid code verifier for public client",
				clientType:   client.Public,
				codeVerifier: invalidCodeVerifier,
			},
			{
				name:         "Code verifier not provided in the request",
				clientType:   client.Public,
				codeVerifier: "",
			},
		}

		for _, test := range tests {
			testContext.WithClient(
				test.clientType,
				[]string{constants.ClientManageScope},
				[]string{constants.AuthorizationCodeGrantType},
			)

			testContext.WithUser([]string{constants.ClientManageScope}, []string{constants.AdminRole})
			testContext.WithUserSession()
			testContext.WithUserConsent()

			authorizationCode := testContext.GetAuthzCodeWithPKCE(testContext.PlainCodeChallenge, client.Plain)
			headers := map[string]string{
				"Cookie":       testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
				"Content-Type": "application/x-www-form-urlencoded",
			}

			formData := url.Values{}
			formData.Add(constants.CodeURLValue, authorizationCode)
			formData.Add(constants.RedirectURIReqField, testRedirectURI)
			formData.Add(constants.StateReqField, testContext.State)
			formData.Add(constants.GrantTypeReqField, constants.AuthorizationCodeGrantType)
			formData.Add(constants.CodeVerifierReqField, test.codeVerifier)

			if test.clientType == client.Confidential {
				headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
			} else {
				formData.Add(constants.ClientIDReqField, testClientID)
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

				testContext.WithClient(test.clientType, []string{constants.ClientManageScope}, []string{constants.RefreshTokenGrantType})
				if test.clientType == client.Public {
					testContext.WithJWTToken(testClientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())
				} else {
					testContext.WithEncryptedJWTToken(testClientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())
				}

				formData := url.Values{}
				formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
				formData.Add(constants.ScopeReqField, constants.ClientManageScope)
				formData.Add(constants.RefreshTokenURLValue, testContext.JWTToken)

				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if test.clientType == client.Confidential {
					headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
				} else {
					formData.Add(constants.ClientIDReqField, testClientID)
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
				assert.Equal(t, constants.BearerAuthHeader, tokenResponse.TokenType)
				assert.Equal(t, 1800, tokenResponse.ExpiresIn)
			})
		}
	})

	t.Run("Invalid request error is returned for missing parameters", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(client.Public, []string{constants.ClientManageScope}, []string{constants.RefreshTokenGrantType})
		testContext.WithJWTToken(testClientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())

		formData := url.Values{}
		formData.Add(constants.ClientIDReqField, testClientID)
		formData.Add(constants.RefreshTokenURLValue, testContext.JWTToken)

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
		testContext.WithClient(client.Public, []string{constants.ClientManageScope}, []string{constants.RefreshTokenGrantType})
		testContext.WithJWTToken(testClientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())

		formData := url.Values{}
		formData.Add(constants.ClientIDReqField, testClientID)
		formData.Add(constants.RefreshTokenURLValue, testContext.JWTToken)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)
		formData.Add(constants.GrantTypeReqField, "invalid-grant-type")

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

		testContext.WithClient(client.Public, []string{constants.ClientManageScope}, []string{constants.RefreshTokenGrantType})

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)
		formData.Add(constants.RefreshTokenURLValue, "invalid-token")
		formData.Add(constants.ClientIDReqField, testClientID)

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

		testContext.WithClient(client.Public, []string{constants.ClientManageScope}, []string{constants.RefreshTokenGrantType})
		testContext.WithExpiredToken()

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)
		formData.Add(constants.RefreshTokenURLValue, testContext.JWTToken)
		formData.Add(constants.ClientIDReqField, testClientID)

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

		testContext.WithClient(client.Public, []string{constants.ClientManageScope}, []string{constants.RefreshTokenGrantType})
		testContext.WithBlacklistedToken(testClientID)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)
		formData.Add(constants.RefreshTokenURLValue, testContext.JWTToken)
		formData.Add(constants.ClientIDReqField, testClientID)

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

		testContext.WithClient(client.Public, []string{constants.ClientManageScope}, []string{constants.AuthorizationCodeGrantType})
		testContext.WithJWTToken(testClientID, time.Duration(5)*time.Minute)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)
		formData.Add(constants.RefreshTokenURLValue, testContext.JWTToken)
		formData.Add(constants.ClientIDReqField, testClientID)

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

		testContext.WithClient(client.Public, []string{constants.ClientReadScope}, []string{constants.RefreshTokenGrantType})
		testContext.WithJWTToken(testClientID, time.Duration(5)*time.Minute)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
		formData.Add(constants.ScopeReqField, constants.ClientManageScope)
		formData.Add(constants.RefreshTokenURLValue, testContext.JWTToken)
		formData.Add(constants.ClientIDReqField, testClientID)

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusForbidden, rr.Code)
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

				testContext.WithClient(test.clientType, []string{constants.TokenIntrospectScope}, []string{constants.AuthorizationCodeGrantType})
				if test.clientType == client.Public {
					testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)
				} else {
					testContext.WithEncryptedJWTToken(testClientID, time.Duration(10)*time.Minute)
				}

				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if test.clientType == client.Confidential {
					headers[constants.AuthorizationHeader] = constants.BasicAuthHeader + encodeClientCredentials(testClientID, testClientSecret)
				} else {
					headers[constants.AuthorizationHeader] = constants.BearerAuthHeader + testContext.JWTToken
				}

				formValue := url.Values{}
				formValue.Add(constants.TokenReqField, testContext.JWTToken)
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
					"Authorization": constants.BasicAuthHeader + encodeClientCredentials("invalidID", testClientSecret),
				},
			},
			{
				name:           "Invalid client error is returned for confidential client with an invalid client secret",
				expectedStatus: http.StatusUnauthorized,
				clientType:     client.Confidential,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": constants.BasicAuthHeader + encodeClientCredentials(testClientID, "invalidSecret"),
				},
			},
			{
				name:           "Invalid client error is returned for public clients",
				expectedStatus: http.StatusUnauthorized,
				clientType:     client.Public,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": constants.BearerAuthHeader + "invalid-token",
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []string{constants.TokenIntrospectScope}, []string{constants.ClientCredentialsGrantType})
				if test.clientType == client.Public {
					testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)
				} else {
					testContext.WithEncryptedJWTToken(testClientID, time.Duration(10)*time.Minute)
				}

				formValue := url.Values{}
				formValue.Add(constants.TokenReqField, testContext.JWTToken)

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

		testContext.WithClient(client.Confidential, []string{constants.TokenIntrospectScope}, []string{constants.ClientCredentialsGrantType})
		testContext.WithExpiredToken()

		formValue := url.Values{}
		formValue.Add(constants.TokenReqField, testContext.JWTToken)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": constants.BasicAuthHeader + encodeClientCredentials(testClientID, testClientSecret),
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

		testContext.WithClient(client.Confidential, []string{constants.TokenIntrospectScope}, []string{constants.ClientCredentialsGrantType})
		testContext.WithBlacklistedToken(testClientID)

		formValue := url.Values{}
		formValue.Add(constants.TokenReqField, testContext.JWTToken)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": constants.BasicAuthHeader + encodeClientCredentials(testClientID, testClientSecret),
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

		testContext.WithClient(client.Confidential, []string{constants.ClientReadScope}, []string{constants.ClientCredentialsGrantType})
		testContext.WithBlacklistedToken(testClientID)

		formValue := url.Values{}
		formValue.Add(constants.TokenReqField, testContext.JWTToken)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": constants.BasicAuthHeader + encodeClientCredentials(testClientID, testClientSecret),
		}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.IntrospectToken,
			strings.NewReader(formValue.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusForbidden, rr.Code)
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

				testContext.WithClient(test.clientType, []string{constants.TokenRevokeScope}, []string{constants.AuthorizationCodeGrantType})
				if test.clientType == client.Public {
					testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)
				} else {
					testContext.WithEncryptedJWTToken(testClientID, time.Duration(10)*time.Minute)
				}

				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if test.clientType == client.Confidential {
					headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
				} else {
					headers["Authorization"] = "Bearer " + testContext.JWTToken
				}

				formValue := url.Values{}
				formValue.Add(constants.TokenReqField, testContext.JWTToken)
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
					"Authorization": constants.BasicAuthHeader + encodeClientCredentials("invalidID", testClientSecret),
				},
			},
			{
				name:           "Invalid client error is returned for confidential client with an invalid client secret",
				expectedStatus: http.StatusUnauthorized,
				clientType:     client.Confidential,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": constants.BasicAuthHeader + encodeClientCredentials(testClientID, "invalidSecret"),
				},
			},
			{
				name:           "Invalid client error is returned for public clients",
				expectedStatus: http.StatusUnauthorized,
				clientType:     client.Public,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": constants.BearerAuthHeader + "invalid-token",
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []string{constants.TokenIntrospectScope}, []string{constants.ClientCredentialsGrantType})
				if test.clientType == client.Public {
					testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)
				} else {
					testContext.WithEncryptedJWTToken(testClientID, time.Duration(10)*time.Minute)
				}

				formValue := url.Values{}
				formValue.Add(constants.TokenReqField, testContext.JWTToken)

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

		testContext.WithClient(client.Confidential, []string{constants.ClientReadScope}, []string{constants.ClientCredentialsGrantType})
		testContext.WithBlacklistedToken(testClientID)

		formValue := url.Values{}
		formValue.Add(constants.TokenReqField, testContext.JWTToken)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": constants.BasicAuthHeader + encodeClientCredentials(testClientID, testClientSecret),
		}

		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.RevokeToken,
			strings.NewReader(formValue.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusForbidden, rr.Code)
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
