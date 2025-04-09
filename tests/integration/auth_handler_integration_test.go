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
			"failed to issue token using the client credentials provided",
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

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidClient, "failed to issue token using the client credentials provided")
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

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidGrant, "failed to issue token using the client credentials provided")
		assert.Equal(t, http.StatusForbidden, rr.Code)
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

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInsufficientScope, "failed to issue token using the client credentials provided")
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

		assert.Equal(t, http.StatusForbidden, rr.Code)
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
