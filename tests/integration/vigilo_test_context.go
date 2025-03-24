package integration

import (
	"bytes"
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
	"github.com/vigiloauth/vigilo/internal/crypto"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	tokenRepo "github.com/vigiloauth/vigilo/internal/repository/token"
	consentRepo "github.com/vigiloauth/vigilo/internal/repository/userconsent"
	tokenService "github.com/vigiloauth/vigilo/internal/service/token"
	"github.com/vigiloauth/vigilo/internal/web"

	users "github.com/vigiloauth/vigilo/internal/domain/user"
	clientRepo "github.com/vigiloauth/vigilo/internal/repository/client"
	userRepo "github.com/vigiloauth/vigilo/internal/repository/user"
)

const (
	// Test constants for reuse
	testUsername        string = "testUser"
	testEmail           string = "test@email.com"
	testPassword1       string = "Password123!@"
	testPassword2       string = "NewPassword_$55"
	testInvalidPassword string = "weak"
	testClientID        string = "test-client-id"
	testUserID          string = "test-user-id"
	testClientSecret    string = "a-string-secret-at-least-256-bits-long"
	testScope           string = "client:manage user:manage"
	testRedirectURI     string = "https://localhost/callback"
	testConsentApproved string = "true"
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
	hashedPassword, err := crypto.HashString(user.Password)
	assert.NoError(tc.T, err)

	user.Password = hashedPassword
	user.ID = testUserID
	userRepo.GetInMemoryUserRepository().AddUser(user)

	tc.User = user
	return tc
}

func (tc *VigiloTestContext) WithUserConsent() *VigiloTestContext {
	consentRepo.GetInMemoryConsentRepository().
		SaveConsent(testUserID, testClientID, testScope)

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
	scopes []string,
	grantTypes []string,
) *VigiloTestContext {
	c := &client.Client{
		ID:            testClientID,
		Type:          clientType,
		Name:          "Test Client",
		RedirectURIS:  []string{testRedirectURI},
		GrantTypes:    grantTypes,
		Scopes:        scopes,
		ResponseTypes: []client.ResponseType{client.CodeResponseType, client.IDTokenResponseType},
	}

	if clientType == client.Confidential {
		c.Secret = testClientSecret
	}

	s := clientRepo.GetInMemoryClientRepository()
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

	tokenService := tokenService.NewTokenServiceImpl(tokenRepo.GetInMemoryTokenRepository())
	userToken, err := tokenService.GenerateToken(tc.User.Email, duration)
	assert.NoError(tc.T, err)

	tc.JWTToken = userToken
	tokenRepo.GetInMemoryTokenRepository().SaveToken(userToken, tc.User.Email, time.Now().Add(duration))

	return tc
}

func (tc *VigiloTestContext) GetSessionCookie() *http.Cookie {
	var sessionCookie *http.Cookie
	for _, cookie := range tc.ResponseRecorder.Result().Cookies() {
		if cookie.Name == "session_token" {
			sessionCookie = cookie
			break
		}
	}
	assert.NotNil(tc.T, sessionCookie)
	return sessionCookie
}

// WithClientCredentialsToken generates and adds a client credentials token
func (tc *VigiloTestContext) WithClientCredentialsToken() *VigiloTestContext {
	if tc.OAuthClient == nil {
		tc.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]string{client.ClientCredentials},
		)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(testClientID + ":" + testClientSecret))
	formData := "grant_type=client_credentials"

	req := httptest.NewRequest(
		http.MethodPost,
		web.OAuthEndpoints.ClientCredentialsToken,
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

	tokenService := tokenService.NewTokenServiceImpl(tokenRepo.GetInMemoryTokenRepository())
	resetToken, err := tokenService.GenerateToken(tc.User.Email, duration)
	assert.NoError(tc.T, err)

	tokenRepo.GetInMemoryTokenRepository().SaveToken(resetToken, tc.User.Email, time.Now().Add(duration))
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

func (tc *VigiloTestContext) WithSession() {
	// Login to create session
	loginRequest := users.NewUserLoginRequest(testUserID, testEmail, testPassword1)
	body, err := json.Marshal(loginRequest)
	assert.NoError(tc.T, err)

	rr := tc.SendHTTPRequest(
		http.MethodPost,
		web.UserEndpoints.Login,
		bytes.NewBuffer(body), nil,
	)

	// assert response is 200 OK
	assert.Equal(tc.T, http.StatusOK, rr.Code)
}

// AssertErrorResponse checks to see if the test returns a correct error.
func (tc *VigiloTestContext) AssertErrorResponse(
	rr *httptest.ResponseRecorder,
	expectedErrCode, expectedDescription string,
) {
	var errResp errors.VigiloAuthError
	err := json.NewDecoder(rr.Body).Decode(&errResp)
	assert.NoError(tc.T, err, "Failed to unmarshal response body")

	assert.Equal(tc.T, expectedErrCode, errResp.ErrorCode)
	assert.Equal(tc.T, expectedDescription, errResp.Details)
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
	userRepo.ResetInMemoryUserRepository()
	tokenRepo.ResetInMemoryTokenRepository()
	clientRepo.ResetInMemoryClientRepository()
	consentRepo.ResetInMemoryConsentRepository()
}
