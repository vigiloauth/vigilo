package integration_tests

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/client"
	store "github.com/vigiloauth/vigilo/internal/client/store"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/utils"
)

const (
	testClientID     string = "testClientID"
	testClientSecret string = "testSecret"
)

func setupAuthHandlerTest(auth string, includeAuth bool) *httptest.ResponseRecorder {
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	formData := "grant_type=client_credentials"

	req := httptest.NewRequest(
		http.MethodPost,
		utils.AuthEndpoints.GenerateToken,
		strings.NewReader(formData),
	)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if includeAuth {
		req.Header.Set("Authorization", "Basic "+auth)
	}

	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	return rr
}

func TestAuthHandler_IssueClientCredentialsToken_Success(t *testing.T) {
	setupClientStore(client.ClientManage, client.ClientCredentials)
	auth := base64.StdEncoding.EncodeToString([]byte(testClientID + ":" + testClientSecret))
	rr := setupAuthHandlerTest(auth, true)

	expectedStatus := http.StatusOK
	assert.Equal(t, expectedStatus, rr.Code)
	assert.NotNil(t, rr.Body)

	var tokenResponse token.TokenResponse
	err := json.NewDecoder(rr.Body).Decode(&tokenResponse)
	assert.NoError(t, err)

	expectedTokenDuration := 30 * time.Minute
	assert.NotNil(t, tokenResponse.AccessToken)
	assert.Equal(t, tokenResponse.TokenType, "Bearer")
	assert.Equal(t, tokenResponse.ExpiresIn, int(expectedTokenDuration.Seconds()))
}

func TestAuthHandler_IssueClientCredentialsToken_AuthenticationFailures(t *testing.T) {
	t.Run("Missing Authorization Header", func(t *testing.T) {
		rr := setupAuthHandlerTest("", false)

		assert.Equal(t, http.StatusBadRequest, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)

		assert.NoError(t, err)
		assert.Equal(t, errResp.ErrorCode, errors.ErrCodeInvalidRequest)
		assert.Contains(t, errResp.ErrorDescription, "invalid authorization header")
	})

	t.Run("Invalid Authorization Header format", func(t *testing.T) {
		auth := base64.StdEncoding.EncodeToString([]byte("invalid_auth_header"))
		rr := setupAuthHandlerTest(auth, true)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)

		assert.NoError(t, err)
		assert.Equal(t, errResp.ErrorCode, errors.ErrCodeInvalidClient)
		assert.Contains(t, errResp.ErrorDescription, "invalid credentials format")
	})

	t.Run("Invalid Client ID", func(t *testing.T) {
		setupClientStore(client.ClientManage, client.ClientCredentials)
		auth := base64.StdEncoding.EncodeToString([]byte("non-existing-ID:" + testClientSecret))
		rr := setupAuthHandlerTest(auth, true)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)

		assert.NoError(t, err)
		assert.Equal(t, errResp.ErrorCode, errors.ErrCodeInvalidClient)
		assert.Contains(t, errResp.Details, "client does not exist with the given ID")
	})

	t.Run("Client Secrets do not match", func(t *testing.T) {
		setupClientStore(client.ClientManage, client.ClientCredentials)
		auth := base64.StdEncoding.EncodeToString([]byte(testClientID + ":invalid-secret"))
		rr := setupAuthHandlerTest(auth, true)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)

		assert.NoError(t, err)
		assert.Equal(t, errResp.ErrorCode, errors.ErrCodeInvalidClient)
		assert.Contains(t, errResp.Details, "invalid `client_secret` provided")
	})

	t.Run("Client is missing required grant types", func(t *testing.T) {
		setupClientStore(client.ClientManage, "")
		auth := base64.StdEncoding.EncodeToString([]byte(testClientID + ":" + testClientSecret))
		rr := setupAuthHandlerTest(auth, true)

		assert.Equal(t, http.StatusForbidden, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)

		assert.NoError(t, err)
		assert.Equal(t, errResp.ErrorCode, errors.ErrCodeInvalidGrantType)
		assert.Contains(t, errResp.Details, "client does not have required grant type `client_credentials`")
	})

	t.Run("Client is missing required scope", func(t *testing.T) {
		setupClientStore("", client.ClientCredentials)
		auth := base64.StdEncoding.EncodeToString([]byte(testClientID + ":" + testClientSecret))
		rr := setupAuthHandlerTest(auth, true)

		assert.Equal(t, http.StatusForbidden, rr.Code)

		var errResp errors.VigiloAuthError
		err := json.NewDecoder(rr.Body).Decode(&errResp)

		assert.NoError(t, err)
		assert.Equal(t, errResp.ErrorCode, errors.ErrCodeInvalidScope)
		assert.Contains(t, errResp.Details, "client does not have required scope `client:manage`")
	})
}

func setupClientStore(scope client.Scope, grant client.GrantType) {
	c := &client.Client{
		ID:            testClientID,
		Secret:        testClientSecret,
		Type:          client.Confidential,
		Name:          "Example Client",
		RedirectURIS:  []string{"https://loaclhost/callback"},
		GrantTypes:    []client.GrantType{client.AuthorizationCode, client.PKCE, grant},
		Scopes:        []client.Scope{client.ClientRead, client.ClientWrite, scope},
		ResponseTypes: []client.ResponseType{client.CodeResponseType, client.IDTokenResponseType},
	}
	s := store.GetInMemoryClientStore()
	s.DeleteClientByID(testClientID)
	_ = s.SaveClient(c)
}
