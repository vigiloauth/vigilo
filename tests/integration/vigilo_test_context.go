package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/crypto"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	userConsent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	sessionRepo "github.com/vigiloauth/vigilo/internal/repository/session"
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
	testClientName1     string = "Test App"
	testClientName2     string = "Test App 2"
	testInvalidPassword string = "weak"
	testClientID        string = "test-client-id"
	testUserID          string = "test-user-id"
	testClientSecret    string = "a-string-secret-at-least-256-bits-long-enough"
	testScope           string = "clients:manage users:manage"
	encodedTestScope    string = "client%3Amanage%20user%3Amanage"
	testRedirectURI     string = "https://vigiloauth.com/callback"
	testConsentApproved string = "true"
	testAuthzCode       string = "valid-auth-code"
)

// VigiloTestContext encapsulates common testing functionality across all test types
type VigiloTestContext struct {
	T                  *testing.T
	VigiloServer       *server.VigiloIdentityServer
	ResponseRecorder   *httptest.ResponseRecorder
	TestServer         *httptest.Server
	HttpClient         *http.Client
	User               *users.User
	OAuthClient        *client.Client
	JWTToken           string
	ClientAuthToken    string
	SessionCookie      *http.Cookie
	State              string
	SH256CodeChallenge string
	PlainCodeChallenge string
}

// NewVigiloTestContext creates a basic test context with default server configurations.
func NewVigiloTestContext(t *testing.T) *VigiloTestContext {
	config.GetServerConfig().Logger().SetLevel("INFO")
	return &VigiloTestContext{
		T:                  t,
		VigiloServer:       server.NewVigiloIdentityServer(),
		SH256CodeChallenge: crypto.EncodeSHA256(testClientSecret),
		PlainCodeChallenge: testClientSecret,
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
	user.Scopes = []string{client.UserManage}
	userRepo.GetInMemoryUserRepository().AddUser(user)

	tc.User = user
	return tc
}

func (tc *VigiloTestContext) WithUserConsent() *VigiloTestContext {
	consentRepo.GetInMemoryUserConsentRepository().SaveConsent(testUserID, testClientID, testScope)

	return tc
}

// WithClient creates and adds a user to the system.
//
// Parameters:
//
// clientType client.ClientType: The type of client (public or confidential).
// scopes []client.Scope: An array of scopes.
// grantTypes []client.GrantType: An array of grantTypes.
func (tc *VigiloTestContext) WithClient(clientType string, scopes []string, grantTypes []string) {
	c := &client.Client{
		Name:          testClientName1,
		ID:            testClientID,
		Type:          clientType,
		Scopes:        scopes,
		GrantTypes:    grantTypes,
		ResponseTypes: []string{client.CodeResponseType},
		RedirectURIS:  []string{testRedirectURI},
	}

	if clientType == client.Confidential {
		c.Secret = testClientSecret
	}

	clientRepo.GetInMemoryClientRepository().SaveClient(c)
}

// WithJWTToken creates and adds a user JWT token to the system.
func (tc *VigiloTestContext) WithJWTToken(id string, duration time.Duration) *VigiloTestContext {
	if tc.User == nil {
		tc.WithUser()
	}

	tokenService := tokenService.NewTokenService(tokenRepo.GetInMemoryTokenRepository())
	token, err := tokenService.GenerateToken(id, testScope, duration)
	assert.NoError(tc.T, err)

	tc.JWTToken = token
	tokenRepo.GetInMemoryTokenRepository().SaveToken(token, id, time.Now().Add(duration))

	return tc
}

func (tc *VigiloTestContext) WithBlacklistedToken(id string) *VigiloTestContext {
	tokenService := tokenService.NewTokenService(tokenRepo.GetInMemoryTokenRepository())
	token, err := tokenService.GenerateToken(id, testScope, config.GetServerConfig().TokenConfig().RefreshTokenDuration())
	assert.NoError(tc.T, err)

	tc.JWTToken = token
	tokenService.BlacklistToken(token)

	return tc
}

func (tc *VigiloTestContext) GetSessionCookie() *http.Cookie {
	var sessionCookie *http.Cookie
	for _, cookie := range tc.ResponseRecorder.Result().Cookies() {
		if cookie.Name == config.GetServerConfig().SessionCookieName() {
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
	formData := url.Values{}
	formData.Add(common.GrantType, client.ClientCredentials)
	formData.Add(common.Scope, client.ClientManage)

	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic " + auth,
	}

	rr := tc.SendHTTPRequest(http.MethodPost, web.OAuthEndpoints.Token, strings.NewReader(formData.Encode()), headers)

	var tokenResponse token.TokenResponse
	err := json.NewDecoder(rr.Body).Decode(&tokenResponse)
	assert.NoError(tc.T, err)
	assert.Equal(tc.T, http.StatusOK, rr.Code)

	tc.ClientAuthToken = tokenResponse.AccessToken
	return tc
}

// WithExpiredToken generates an expired token for testing.
func (tc *VigiloTestContext) WithExpiredToken() *VigiloTestContext {
	return tc.WithJWTToken(testEmail, -1*time.Hour)
}

// WithPasswordResetToken generates a password reset token.
func (tc *VigiloTestContext) WithPasswordResetToken(duration time.Duration) (string, *VigiloTestContext) {
	if tc.User == nil {
		tc.WithUser()
	}

	tokenService := tokenService.NewTokenService(tokenRepo.GetInMemoryTokenRepository())
	resetToken, err := tokenService.GenerateToken(tc.User.Email, testScope, duration)
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

func (tc *VigiloTestContext) ClearSession() {
	sessionRepo.ResetInMemorySessionRepository()
}

func (tc *VigiloTestContext) WithOAuthLogin() {
	loginRequest := users.UserLoginRequest{
		ID:       testUserID,
		Username: testUsername,
		Password: testPassword1,
	}

	requestBody, err := json.Marshal(loginRequest)
	assert.NoError(tc.T, err)

	// state := tc.GetStateFromSession()
	// tc.State = state

	queryParams := url.Values{}
	queryParams.Add(common.ClientID, testClientID)
	queryParams.Add(common.RedirectURI, testRedirectURI)
	// queryParams.Add(common.State, state)
	endpoint := web.OAuthEndpoints.Login + "?" + queryParams.Encode()

	rr := tc.SendHTTPRequest(
		http.MethodPost,
		endpoint,
		bytes.NewReader(requestBody), nil,
	)

	tc.T.Log(rr.Body.String())
	assert.Equal(tc.T, http.StatusOK, rr.Code)
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

func (tc *VigiloTestContext) WithUserSession() {
	if tc.User == nil {
		tc.WithUser()
	}

	loginRequest := users.NewUserLoginRequest(testUserID, testEmail, testPassword1)
	body, err := json.Marshal(loginRequest)
	assert.NoError(tc.T, err)

	rr := tc.SendHTTPRequest(
		http.MethodPost,
		web.UserEndpoints.Login,
		bytes.NewBuffer(body), nil,
	)

	assert.Equal(tc.T, http.StatusOK, rr.Code)

	// Store the session cookie
	cookies := rr.Result().Cookies()
	for _, cookie := range cookies {
		if cookie.Name == config.GetServerConfig().SessionCookieName() {
			tc.SessionCookie = cookie
			return
		}
	}

	tc.T.Fatalf("Session cookie not found in login response")
}

func (tc *VigiloTestContext) GetStateFromSession() string {
	queryParams := url.Values{}
	queryParams.Add(common.ClientID, testClientID)
	queryParams.Add(common.RedirectURI, testRedirectURI)
	queryParams.Add(common.Scope, testScope)
	getEndpoint := web.OAuthEndpoints.UserConsent + "?" + queryParams.Encode()

	headers := map[string]string{"Cookie": tc.SessionCookie.Name + "=" + tc.SessionCookie.Value}

	rr := tc.SendHTTPRequest(http.MethodGet, getEndpoint, nil, headers)
	assert.Equal(tc.T, http.StatusOK, rr.Code)

	// Parse the response to extract the state
	var consentResponse userConsent.UserConsentResponse
	err := json.Unmarshal(rr.Body.Bytes(), &consentResponse)
	assert.NoError(tc.T, err)
	state := consentResponse.State
	assert.NotEmpty(tc.T, state)

	return state
}

func (tc *VigiloTestContext) GetAuthzCode() string {
	queryParams := tc.CreateAuthorizationCodeRequestQueryParams("", "")
	parsedURL := tc.sendAuthorizationCodeRequest(queryParams)

	authzCode := parsedURL.Query().Get(client.CodeResponseType)
	assert.NotEmpty(tc.T, authzCode, "Authorization code should not be empty")

	return authzCode
}

func (tc *VigiloTestContext) CreateAuthorizationCodeRequestQueryParams(codeChallenge, codeChallengeMethod string) url.Values {
	queryParams := url.Values{}
	queryParams.Add(common.ResponseType, client.CodeResponseType)
	queryParams.Add(common.ClientID, testClientID)
	queryParams.Add(common.RedirectURI, testRedirectURI)
	queryParams.Add(common.Scope, client.ClientManage)
	queryParams.Add(common.State, tc.State)
	queryParams.Add(common.Approved, "true")

	if codeChallenge != "" {
		queryParams.Add(common.CodeChallenge, codeChallenge)
	}
	if codeChallengeMethod != "" {
		queryParams.Add(common.CodeChallengeMethod, codeChallengeMethod)
	}

	return queryParams
}

func (tc *VigiloTestContext) GetAuthzCodeWithPKCE(codeChallenge, codeChallengeMethod string) string {
	queryParams := tc.CreateAuthorizationCodeRequestQueryParams(codeChallenge, codeChallengeMethod)
	parsedURL := tc.sendAuthorizationCodeRequest(queryParams)

	authzCode := parsedURL.Query().Get(common.AuthzCode)
	assert.NotEmpty(tc.T, authzCode, "Authorization code should not be empty")

	return authzCode
}

// AssertErrorResponseDescription checks to see if the test returns a correct error.
func (tc *VigiloTestContext) AssertErrorResponseDescription(
	rr *httptest.ResponseRecorder,
	expectedErrCode, expectedDescription string,
) {
	errResp := tc.decodeErrorResponse(rr)
	assert.Equal(tc.T, expectedErrCode, errResp.ErrorCode)
	assert.Equal(tc.T, expectedDescription, errResp.ErrorDescription)
}

func (tc *VigiloTestContext) AssertErrorResponseDetails(
	rr *httptest.ResponseRecorder,
	expectedErrCode, expectedDetails string,
) {
	errResp := tc.decodeErrorResponse(rr)
	assert.Equal(tc.T, expectedErrCode, errResp.ErrorCode)
	assert.Equal(tc.T, expectedDetails, errResp.ErrorDetails)
}

func (tc *VigiloTestContext) AssertErrorResponse(
	rr *httptest.ResponseRecorder,
	expectedErrCode, expectedDescription, expectedDetails string,
) {
	errResp := tc.decodeErrorResponse(rr)
	assert.Equal(tc.T, expectedErrCode, errResp.ErrorCode)
	assert.Equal(tc.T, expectedDescription, errResp.ErrorDescription)
	assert.Equal(tc.T, expectedDetails, errResp.ErrorDetails)
}

// TearDown performs cleanup operations.
func (tc *VigiloTestContext) TearDown() {
	if tc.TestServer != nil {
		tc.TestServer.Close()
	}
	resetInMemoryStores()
}

func (tc *VigiloTestContext) sendAuthorizationCodeRequest(queryParams url.Values) *url.URL {
	endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()
	headers := map[string]string{"Cookie": tc.SessionCookie.Name + "=" + tc.SessionCookie.Value}

	rr := tc.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)
	assert.Equal(tc.T, http.StatusFound, rr.Code)

	location := rr.Header().Get(common.Location)
	assert.NotEmpty(tc.T, location, "Redirect location should not be empty")

	parsedURL, err := url.Parse(location)
	assert.NoError(tc.T, err)

	return parsedURL
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
	consentRepo.ResetInMemoryUserConsentRepository()
	sessionRepo.ResetInMemorySessionRepository()
}

func (tc *VigiloTestContext) decodeErrorResponse(rr *httptest.ResponseRecorder) errors.VigiloAuthError {
	var errResp errors.VigiloAuthError
	err := json.NewDecoder(rr.Body).Decode(&errResp)
	assert.NoError(tc.T, err, "Failed to unmarshal response body")
	return errResp
}
