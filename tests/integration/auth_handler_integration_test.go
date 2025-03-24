package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestAuthHandler_IssueClientCredentialsToken_Success(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage},
		[]client.GrantType{client.ClientCredentials},
	)

	headers := generateHeaderWithCredentials(testClientID, testClientSecret)
	rr := sendTokenGenerationRequest(testContext, headers)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.NotNil(t, rr.Body)

	var tokenResponse token.TokenResponse
	err := json.NewDecoder(rr.Body).Decode(&tokenResponse)
	assert.NoError(t, err)

	assert.NotNil(t, tokenResponse.AccessToken)
	assert.Equal(t, "Bearer", tokenResponse.TokenType)
	assert.Equal(t, 1800, tokenResponse.ExpiresIn)
}

func TestAuthHandler_IssueClientCredentialsToken_AuthenticationFailures(t *testing.T) {
	t.Run("Missing Authorization Header", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)

		headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		rr := sendTokenGenerationRequest(testContext, headers)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)
		assert.NoError(t, err)

		assert.Equal(t, errors.ErrCodeInvalidClient, errResp.ErrorCode)
		assert.Contains(t, errResp.ErrorDescription, "invalid authorization header")
	})

	t.Run("Invalid Authorization Header format", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)

		headers := map[string]string{
			"Content-Type":  "application/x-www-form-urlencoded",
			"Authorization": "Basic invalid_credentials",
		}

		rr := sendTokenGenerationRequest(testContext, headers)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)
		assert.NoError(t, err)

		assert.Equal(t, errors.ErrCodeInvalidClient, errResp.ErrorCode)
		assert.Contains(t, errResp.ErrorDescription, "invalid credentials")
	})

	t.Run("Invalid Client ID", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]client.GrantType{client.ClientCredentials},
		)

		headers := generateHeaderWithCredentials("non-existing-id", testClientSecret)
		rr := sendTokenGenerationRequest(testContext, headers)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)
		assert.NoError(t, err)

		assert.Equal(t, errors.ErrCodeInvalidClient, errResp.ErrorCode)
		assert.Contains(t, errResp.Details, "client does not exist with the given ID")
	})

	t.Run("Client Secrets do not match", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]client.GrantType{client.ClientCredentials},
		)

		headers := generateHeaderWithCredentials(testClientID, "invalid-secret")
		rr := sendTokenGenerationRequest(testContext, headers)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)
		assert.NoError(t, err)

		assert.Equal(t, errors.ErrCodeInvalidClient, errResp.ErrorCode)
		assert.Contains(t, errResp.Details, "invalid 'client_secret' provided")
	})

	t.Run("Client is missing required grant types", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]client.GrantType{}, // No grant types
		)

		headers := generateHeaderWithCredentials(testClientID, testClientSecret)
		rr := sendTokenGenerationRequest(testContext, headers)
		assert.Equal(t, http.StatusForbidden, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)

		assert.NoError(t, err)
		assert.Equal(t, errors.ErrCodeInvalidGrantType, errResp.ErrorCode)
		assert.Contains(t, errResp.Details, "client does not have required grant type 'client_credentials'")
	})

	t.Run("Client is missing required scope", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			[]string{}, // No scopes
			[]client.GrantType{client.ClientCredentials},
		)

		headers := generateHeaderWithCredentials(testClientID, testClientSecret)
		rr := sendTokenGenerationRequest(testContext, headers)
		assert.Equal(t, http.StatusForbidden, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)
		assert.NoError(t, err)

		assert.Equal(t, errors.ErrCodeInvalidScope, errResp.ErrorCode)
		assert.Contains(t, errResp.Details, "client does not have required scope 'client:manage'")
	})
}

func sendTokenGenerationRequest(testContext *VigiloTestContext, headers map[string]string) *httptest.ResponseRecorder {
	return testContext.SendHTTPRequest(
		http.MethodPost,
		web.OAuthEndpoints.GenerateToken,
		strings.NewReader("grant_type=client_credentials"),
		headers,
	)
}

func generateHeaderWithCredentials(id, secret string) map[string]string {
	return map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic " + encodeClientCredentials(id, secret),
	}
}

func encodeClientCredentials(clientID, clientSecret string) string {
	return base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
}
