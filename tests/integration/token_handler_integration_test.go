package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

func TestTokenHandler_IssueTokens_ClientCredentialsGrant(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name         string
			clientType   types.ClientType
			clientSecret string
		}{
			{
				name:         "Error is successfully returned when the client is public",
				clientType:   types.PublicClient,
				clientSecret: "",
			},
			{
				name:         "Success when client is confidential",
				clientType:   types.ConfidentialClient,
				clientSecret: testClientSecret,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(
					test.clientType,
					[]types.Scope{types.OpenIDScope},
					[]string{constants.ClientCredentialsGrantType},
				)

				formData := url.Values{}
				formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
				formData.Add(constants.ScopeReqField, types.OpenIDScope.String())

				headers := GenerateHeaderWithCredentials(testClientID, test.clientSecret)

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
				require.NoError(t, err)

				assert.NotNil(t, tokenResponse.AccessToken)
				assert.Equal(t, "bearer", tokenResponse.TokenType)
				assert.Equal(t, int64(1800), tokenResponse.ExpiresIn)
			})
		}
	})

	t.Run("Error is returned when the client ID is invalid", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(
			types.ConfidentialClient,
			[]types.Scope{types.OpenIDScope},
			[]string{constants.ClientCredentialsGrantType},
		)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())

		headers := GenerateHeaderWithCredentials("non-existing-id", testClientSecret)
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
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())

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
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())

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
			types.ConfidentialClient,
			[]types.Scope{types.OpenIDScope},
			[]string{constants.ClientCredentialsGrantType},
		)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
		headers := GenerateHeaderWithCredentials(testClientID, "invalid-secret")

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
			types.ConfidentialClient,
			[]types.Scope{types.OpenIDScope},
			[]string{constants.AuthorizationCodeGrantType}, // unsupported grant type
		)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())

		headers := GenerateHeaderWithCredentials(testClientID, testClientSecret)
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeUnauthorizedClient, "invalid client credentials or unauthorized grant type/scopes")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestTokenHandler_IssueTokens_PasswordGrant(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name         string
			clientType   types.ClientType
			clientSecret string
		}{
			{
				name:         "Success when client is confidential",
				clientType:   types.ConfidentialClient,
				clientSecret: testClientSecret,
			},
			{
				name:         "Error is successfully returned when the client is public",
				clientType:   types.PublicClient,
				clientSecret: "",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []types.Scope{types.OpenIDScope}, []string{constants.PasswordGrantType})
				testContext.WithUser([]string{constants.AdminRole})

				formData := url.Values{}
				formData.Add(constants.GrantTypeReqField, constants.PasswordGrantType)
				formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
				formData.Add(constants.UsernameReqField, testUsername)
				formData.Add(constants.PasswordReqField, testPassword1)

				headers := GenerateHeaderWithCredentials(testClientID, test.clientSecret)
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
				require.NoError(t, err)

				assert.NotNil(t, tokenResponse.AccessToken)
				assert.Equal(t, "bearer", tokenResponse.TokenType)
				assert.Equal(t, int64(1800), tokenResponse.ExpiresIn)
			})
		}
	})

	t.Run("Error is returned when client authentication fails", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(types.ConfidentialClient, []types.Scope{types.OpenIDScope}, []string{constants.PasswordGrantType})
		testContext.WithUser([]string{constants.AdminRole})

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.PasswordGrantType)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
		formData.Add(constants.UsernameReqField, testUsername)
		formData.Add(constants.PasswordReqField, testPassword1)

		headers := GenerateHeaderWithCredentials("non-existing-id", testClientSecret)
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

		testContext.WithClient(types.ConfidentialClient, []types.Scope{types.OpenIDScope}, []string{constants.PasswordGrantType})
		testContext.WithUser([]string{constants.AdminRole})

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.PasswordGrantType)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
		formData.Add(constants.UsernameReqField, testUsername)
		formData.Add(constants.PasswordReqField, "invalid-password")

		headers := GenerateHeaderWithCredentials(testClientID, testClientSecret)
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.Token,
			strings.NewReader(formData.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Error is returned when client secrets do not match", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(types.ConfidentialClient, []types.Scope{types.OpenIDScope}, []string{constants.PasswordGrantType})
		testContext.WithUser([]string{constants.AdminRole})

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.PasswordGrantType)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
		formData.Add(constants.UsernameReqField, testUsername)
		formData.Add(constants.PasswordReqField, testPassword1)

		headers := GenerateHeaderWithCredentials(testClientID, "invalid-secret")
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
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	testContext.WithUserSession()
	testContext.WithUserConsent()
	testContext.WithClient(types.ConfidentialClient, []types.Scope{}, []string{constants.AuthorizationCodeGrantType})
	testContext.WithUser([]string{constants.AdminRole})

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
	t.Logf("body: %v", rr.Body)
	assert.Equal(t, http.StatusOK, rr.Code, "Expected a successful token exchange")
}

func TestTokenHandler_TokenExchange_UsingPKCE(t *testing.T) {
	t.Run("Success when client is using PKCE", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		tests := []struct {
			name                string
			clientType          types.ClientType
			codeChallengeMethod types.CodeChallengeMethod
			codeChallenge       string
			codeVerifier        string
		}{
			{
				name:                "Success when public client uses plain method",
				clientType:          types.PublicClient,
				codeChallengeMethod: types.PlainCodeChallengeMethod,
				codeChallenge:       testContext.PlainCodeChallenge,
				codeVerifier:        testContext.PlainCodeChallenge,
			},
			{
				name:                "Success when public client uses SHA-256 method",
				clientType:          types.PublicClient,
				codeChallengeMethod: types.SHA256CodeChallengeMethod,
				codeChallenge:       testContext.SH256CodeChallenge,
				codeVerifier:        testClientSecret,
			},
		}

		for _, test := range tests {
			testContext.WithClient(
				test.clientType, []types.Scope{},
				[]string{constants.AuthorizationCodeGrantType},
			)

			testContext.WithUser([]string{constants.AdminRole})
			testContext.WithUserSession()
			testContext.WithUserConsent()

			authorizationCode := testContext.GetAuthzCodeWithPKCE(test.codeChallenge, test.codeChallengeMethod.String())
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

			if test.clientType == types.ConfidentialClient {
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
			clientType   types.ClientType
			codeVerifier string
		}{
			{
				name:         "Invalid code verifier for public client",
				clientType:   types.PublicClient,
				codeVerifier: invalidCodeVerifier,
			},
			{
				name:         "Code verifier not provided in the request",
				clientType:   types.PublicClient,
				codeVerifier: "",
			},
		}

		for _, test := range tests {
			testContext.WithClient(
				test.clientType, []types.Scope{},
				[]string{constants.AuthorizationCodeGrantType},
			)

			testContext.WithUser([]string{constants.AdminRole})
			testContext.WithUserSession()
			testContext.WithUserConsent()

			authorizationCode := testContext.GetAuthzCodeWithPKCE(testContext.PlainCodeChallenge, types.PlainCodeChallengeMethod.String())
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

			if test.clientType == types.ConfidentialClient {
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
			clientType types.ClientType
		}{
			{
				name:       "Success when the client is confidential",
				clientType: types.ConfidentialClient,
			},
			{
				name:       "Success when the client is public",
				clientType: types.PublicClient,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []types.Scope{}, []string{constants.RefreshTokenGrantType})
				testContext.WithJWTToken(testClientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())

				formData := url.Values{}
				formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
				formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
				formData.Add(constants.RefreshTokenURLValue, testContext.JWTToken)

				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if test.clientType == types.ConfidentialClient {
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
				require.NoError(t, err)

				assert.NotNil(t, tokenResponse.AccessToken)
				assert.Equal(t, "bearer", tokenResponse.TokenType)
				assert.Equal(t, int64(1800), tokenResponse.ExpiresIn)
			})
		}
	})

	t.Run("Invalid request error is returned for missing parameters", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(types.PublicClient, []types.Scope{}, []string{constants.RefreshTokenGrantType})
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
		testContext.WithClient(types.PublicClient, []types.Scope{}, []string{constants.RefreshTokenGrantType})
		testContext.WithJWTToken(testClientID, config.GetServerConfig().TokenConfig().RefreshTokenDuration())

		formData := url.Values{}
		formData.Add(constants.ClientIDReqField, testClientID)
		formData.Add(constants.RefreshTokenURLValue, testContext.JWTToken)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
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

		testContext.WithClient(types.PublicClient, []types.Scope{}, []string{constants.RefreshTokenGrantType})

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
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

	t.Run("Invalid grant error is returned when the refresh token is blacklisted", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(types.PublicClient, []types.Scope{}, []string{constants.RefreshTokenGrantType})
		testContext.WithBlacklistedToken(testClientID)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
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

		testContext.WithClient(types.PublicClient, []types.Scope{}, []string{constants.AuthorizationCodeGrantType})
		testContext.WithJWTToken(testClientID, time.Duration(5)*time.Minute)

		formData := url.Values{}
		formData.Add(constants.GrantTypeReqField, constants.RefreshTokenGrantType)
		formData.Add(constants.ScopeReqField, types.OpenIDScope.String())
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
}

func TestTokenHandler_IntrospectToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name       string
			clientType types.ClientType
		}{
			{
				name:       "Successful response for confidential clients",
				clientType: types.ConfidentialClient,
			},
			{
				name:       "Successful response for public clients",
				clientType: types.PublicClient,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []types.Scope{types.TokenIntrospectScope}, []string{constants.AuthorizationCodeGrantType})
				testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)

				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if test.clientType == types.ConfidentialClient {
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
			clientType     types.ClientType
			headers        map[string]string
			expectedStatus int
		}{
			{
				name:           "Invalid client error is returned for confidential client with an invalid client ID",
				clientType:     types.ConfidentialClient,
				expectedStatus: http.StatusUnauthorized,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": constants.BasicAuthHeader + encodeClientCredentials("invalidID", testClientSecret),
				},
			},
			{
				name:           "Invalid client error is returned for confidential client with an invalid client secret",
				expectedStatus: http.StatusUnauthorized,
				clientType:     types.ConfidentialClient,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": constants.BasicAuthHeader + encodeClientCredentials(testClientID, "invalidSecret"),
				},
			},
			{
				name:           "Invalid client error is returned for public clients",
				expectedStatus: http.StatusUnauthorized,
				clientType:     types.PublicClient,
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

				testContext.WithClient(test.clientType, []types.Scope{types.TokenIntrospectScope}, []string{constants.ClientCredentialsGrantType})
				testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)

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

	t.Run("Active is set to false when the requested token is blacklisted", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		testContext.WithClient(types.ConfidentialClient, []types.Scope{types.TokenIntrospectScope}, []string{constants.ClientCredentialsGrantType})
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
		require.NoError(t, err)

		assert.False(t, tokenResponse.Active)
	})
}

func TestTokenHandler_RevokeToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name       string
			clientType types.ClientType
		}{
			{
				name:       "Successful response for confidential clients",
				clientType: types.ConfidentialClient,
			},
			{
				name:       "Successful response for public clients",
				clientType: types.PublicClient,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithClient(test.clientType, []types.Scope{types.TokenRevokeScope}, []string{constants.AuthorizationCodeGrantType})
				testContext.WithJWTToken(testUserID, time.Duration(10)*time.Minute)

				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if test.clientType == types.ConfidentialClient {
					headers["Authorization"] = "Basic " + encodeClientCredentials(testClientID, testClientSecret)
				} else {
					headers["Authorization"] = "bearer " + testContext.JWTToken
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
			clientType     types.ClientType
			headers        map[string]string
			expectedStatus int
		}{
			{
				name:           "Invalid client error is returned for confidential client with an invalid client ID",
				clientType:     types.ConfidentialClient,
				expectedStatus: http.StatusUnauthorized,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": constants.BasicAuthHeader + encodeClientCredentials("invalidID", testClientSecret),
				},
			},
			{
				name:           "Invalid client error is returned for confidential client with an invalid client secret",
				clientType:     types.ConfidentialClient,
				expectedStatus: http.StatusUnauthorized,
				headers: map[string]string{
					"Content-Type":  "application/x-www-form-urlencoded",
					"Authorization": constants.BasicAuthHeader + encodeClientCredentials(testClientID, "invalidSecret"),
				},
			},
			{
				name:           "Invalid client error is returned for public clients",
				clientType:     types.PublicClient,
				expectedStatus: http.StatusUnauthorized,
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

				testContext.WithClient(test.clientType, []types.Scope{types.TokenIntrospectScope}, []string{constants.ClientCredentialsGrantType})
				testContext.WithJWTToken(testClientID, time.Duration(10)*time.Minute)

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

		testContext.WithClient(types.ConfidentialClient, []types.Scope{types.OpenIDScope}, []string{constants.ClientCredentialsGrantType})
		testContext.WithBlacklistedToken(testClientID)

		formValue := url.Values{}
		formValue.Add(constants.TokenReqField, testContext.JWTToken)

		headers := GenerateHeaderWithCredentials(testClientID, testClientSecret)
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.OAuthEndpoints.RevokeToken,
			strings.NewReader(formValue.Encode()),
			headers,
		)

		assert.Equal(t, http.StatusForbidden, rr.Code)
	})
}

func TestTokenHandler_CodeReuseFailsAndRevokesAccessToken(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	testContext.WithUser([]string{constants.AdminRole})
	testContext.WithUserConsent()
	testContext.WithUserSession()
	testContext.WithClient(
		types.ConfidentialClient,
		[]types.Scope{},
		[]string{constants.AuthorizationCodeGrantType},
	)

	// 1. Make request to AuthorizeClient endpoint
	code := testContext.GetAuthzCode()

	// 2. Get Access Token using code from AuthorizeClient
	formData := url.Values{}
	formData.Add(constants.CodeURLValue, code)
	formData.Add(constants.RedirectURIReqField, testRedirectURI)
	formData.Add(constants.StateReqField, testContext.State)
	formData.Add(constants.GrantTypeReqField, constants.AuthorizationCodeGrantType)

	headers := map[string]string{
		"Cookie":        testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic " + encodeClientCredentials(testClientID, testClientSecret),
	}

	rr := testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)
	assert.Equal(t, http.StatusOK, rr.Code, "Expected status to be '200 OK'")

	var tokenResponse token.TokenResponse
	err := json.NewDecoder(rr.Body).Decode(&tokenResponse)
	require.NoError(t, err, "Expected no error while decoding token response")

	// 3. Call UserInfo with Access token
	headers = map[string]string{
		constants.AuthorizationHeader: constants.BearerAuthHeader + tokenResponse.AccessToken,
	}
	rr = testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.UserInfo, nil, headers)
	assert.Equal(t, http.StatusOK, rr.Code, "Expected status to be '200 OK'")

	// 4. Use same authorization code to get an access token. Original access token should be revoked
	headers = map[string]string{
		"Cookie":        testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic " + encodeClientCredentials(testClientID, testClientSecret),
	}

	rr = testContext.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)
	assert.Equal(t, http.StatusBadRequest, rr.Code, "Expected status to be '400 Bad Request'")

	// 5. Attempt to use Access Token again. It should have previously been revoked.
	headers = map[string]string{
		constants.AuthorizationHeader: constants.BearerAuthHeader + tokenResponse.AccessToken,
	}
	rr = testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.UserInfo, nil, headers)
	assert.Equal(t, http.StatusUnauthorized, rr.Code, "Expected status to be '401 Unauthorized'")
}
