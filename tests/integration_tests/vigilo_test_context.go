package integration_tests

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/client"
	clientStore "github.com/vigiloauth/vigilo/internal/client/store"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

const (
	// Test constants for reuse
	testUsername        string = "testUser"
	testEmail           string = "test@email.com"
	testPassword1       string = "Password123!@"
	testPassword2       string = "NewPassword_$55"
	testInvalidPassword string = "weak"
	testClientID        string = "test-client-id"
	testClientSecret    string = "a-string-secret-at-least-256-bits-long"
)

// VigiloTestContext encapsulates common testing functionality across all test types
type VigiloTestContext struct {
	T                *testing.T
	VigiloServer     *server.VigiloIdentityServer
	ResponseRecorder *httptest.ResponseRecorder
	TestServer       *httptest.Server
	HttpClient       *http.Client
	User             *users.User
	OAuthClient      *client.Client
	JWTToken         string
	ClientAuthToken  string
}

// NewVigiloTestContext creates a basic test context with default server configurations.
func NewVigiloTestContext(t *testing.T) *VigiloTestContext {
	resetInMemoryStores()
	vigiloServer := server.NewVigiloIdentityServer()
	config.NewServerConfig()

	return &VigiloTestContext{
		T:                t,
		VigiloServer:     vigiloServer,
		ResponseRecorder: httptest.NewRecorder(),
		HttpClient:       &http.Client{},
	}
}

// WithLiveServer adds a live test server to the context.
func (tc *VigiloTestContext) WithLiveHTTPServer() *VigiloTestContext {
	tc.TestServer = httptest.NewServer(tc.VigiloServer.Router())
	return tc
}

// WithUser creates and adds a user to the system.
func (tc *VigiloTestContext) WithUser() *VigiloTestContext {
	user := users.NewUser(testUsername, testEmail, testPassword1)
	hashedPassword, err := utils.HashString(user.Password)
	assert.NoError(tc.T, err)

	user.Password = hashedPassword
	users.GetInMemoryUserStore().AddUser(user)

	tc.User = user
	return tc
}

// WithClient creates and adds a user to the system.
//
// Parameters:
//
// clientType client.ClientType: The type of client (public or confidential).
// scopes []client.Scope: An array of scopes.
// grantTypes []client.GrantType: An array of grantTypes.
func (tc *VigiloTestContext) WithClient(
	clientType client.ClientType,
	scopes []client.Scope,
	grantTypes []client.GrantType,
) *VigiloTestContext {
	c := &client.Client{
		ID:            testClientID,
		Type:          clientType,
		Name:          "Test Client",
		RedirectURIS:  []string{"https://localhost/callback"},
		GrantTypes:    grantTypes,
		Scopes:        scopes,
		ResponseTypes: []client.ResponseType{client.CodeResponseType, client.IDTokenResponseType},
	}

	if clientType == client.Confidential {
		c.Secret = testClientSecret
	}

	s := clientStore.GetInMemoryClientStore()
	err := s.SaveClient(c)
	assert.NoError(tc.T, err)

	tc.OAuthClient = c
	return tc
}

// WithUserToken creates and adds a user JWT token to the system.
func (tc *VigiloTestContext) WithUserToken(duration time.Duration) *VigiloTestContext {
	if tc.User == nil {
		tc.WithUser()
	}

	tokenService := token.NewTokenService(token.GetInMemoryTokenStore())
	userToken, err := tokenService.GenerateToken(tc.User.Email, duration)
	assert.NoError(tc.T, err)

	tc.JWTToken = userToken
	token.GetInMemoryTokenStore().SaveToken(userToken, tc.User.Email, time.Now().Add(duration))

	return tc
}

// WithClientCredentialsToken generates and adds a client credentials token
func (tc *VigiloTestContext) WithClientCredentialsToken() *VigiloTestContext {
	if tc.OAuthClient == nil {
		tc.WithClient(
			client.Confidential,
			[]client.Scope{client.ClientManage},
			[]client.GrantType{client.ClientCredentials},
		)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(testClientID + ":" + testClientSecret))
	formData := "grant_type=client_credentials"

	req := httptest.NewRequest(
		http.MethodPost,
		utils.AuthEndpoints.GenerateToken,
		strings.NewReader(formData),
	)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+auth)

	rr := httptest.NewRecorder()
	tc.VigiloServer.Router().ServeHTTP(rr, req)

	var tokenResponse token.TokenResponse
	err := json.NewDecoder(rr.Body).Decode(&tokenResponse)
	assert.NoError(tc.T, err)
	assert.Equal(tc.T, http.StatusOK, rr.Code)

	tc.ClientAuthToken = tokenResponse.AccessToken
	return tc
}

// WithExpiredUserToken generates an expired token for testing.
func (tc *VigiloTestContext) WithExpiredUserToken() *VigiloTestContext {
	return tc.WithUserToken(-1 * time.Hour)
}

// WithPasswordResetToken generates a password reset token.
func (tc *VigiloTestContext) WithPasswordResetToken(duration time.Duration) (string, *VigiloTestContext) {
	if tc.User == nil {
		tc.WithUser()
	}

	tokenService := token.NewTokenService(token.GetInMemoryTokenStore())
	resetToken, err := tokenService.GenerateToken(tc.User.Email, duration)
	assert.NoError(tc.T, err)

	token.GetInMemoryTokenStore().SaveToken(resetToken, tc.User.Email, time.Now().Add(duration))
	return resetToken, tc
}

// WithCustomConfig sets a custom server configuration
func (tc *VigiloTestContext) WithCustomConfig(options ...config.ServerConfigOptions) *VigiloTestContext {
	config.NewServerConfig(options...)
	tc.VigiloServer = server.NewVigiloIdentityServer()
	return tc
}

// SendHTTPRequest sends an HTTP request using the test recorder
func (tc *VigiloTestContext) SendHTTPRequest(method, endpoint string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, endpoint, body)

	tc.addHeaderAuth(req, headers)

	rr := httptest.NewRecorder()
	tc.VigiloServer.Router().ServeHTTP(rr, req)
	tc.ResponseRecorder = rr
	return rr
}

// SendLiveRequest sends a request to the live test server
func (tc *VigiloTestContext) SendLiveRequest(method, endpoint string, body io.Reader, headers map[string]string) (*http.Response, error) {
	if tc.TestServer == nil {
		tc.WithLiveHTTPServer()
	}

	url := tc.TestServer.URL + endpoint
	req, err := http.NewRequest(method, url, body)
	assert.NoError(tc.T, err)

	tc.addHeaderAuth(req, headers)

	return tc.HttpClient.Do(req)
}

// TearDown performs cleanup operations.
func (tc *VigiloTestContext) TearDown() {
	if tc.TestServer != nil {
		tc.TestServer.Close()
	}
}

func (tc *VigiloTestContext) addHeaderAuth(req *http.Request, headers map[string]string) {
	if _, exists := headers["Content-Type"]; !exists {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add all headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if tc.JWTToken != "" && headers["Authorization"] == "" {
		req.Header.Set("Authorization", "Bearer "+tc.JWTToken)
	} else if tc.ClientAuthToken != "" && headers["Authorization"] == "" {
		req.Header.Set("Authorization", "Bearer "+tc.ClientAuthToken)
	}
}

func resetInMemoryStores() {
	users.ResetInMemoryUserStore()
	token.ResetInMemoryTokenStore()
	clientStore.ResetInMemoryClientStore()
}
