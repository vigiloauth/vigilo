package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/idp/server"
	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/internal/crypto"
	audit "github.com/vigiloauth/vigilo/internal/domain/audit"

	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	userConsent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	auditEventRepo "github.com/vigiloauth/vigilo/internal/repository/audit"
	sessionRepo "github.com/vigiloauth/vigilo/internal/repository/session"
	tokenRepo "github.com/vigiloauth/vigilo/internal/repository/token"
	consentRepo "github.com/vigiloauth/vigilo/internal/repository/userconsent"
	tokenService "github.com/vigiloauth/vigilo/internal/service/token"
	"github.com/vigiloauth/vigilo/internal/utils"

	"github.com/vigiloauth/vigilo/internal/web"

	users "github.com/vigiloauth/vigilo/internal/domain/user"
	clientRepo "github.com/vigiloauth/vigilo/internal/repository/client"
	userRepo "github.com/vigiloauth/vigilo/internal/repository/user"
)

const (
	// Test constants for reuse
	testUsername        string = "testUser"
	testFirstName       string = "John"
	testMiddleName      string = "Mary"
	testFamilyName      string = "Doe"
	testBirthdate       string = "2000-12-06"
	testPhoneNumber     string = "+14255551212"
	testGender          string = "male"
	testStreetAddress   string = "123 Main St"
	testLocality        string = "Springfield"
	testRegion          string = "IL"
	testPostalCode      string = "62704"
	testCountry         string = "USA"
	testEmail           string = "test@email.com"
	testPassword1       string = "Password123!@"
	testPassword2       string = "NewPassword_$55"
	testClientName1     string = "Test App"
	testClientName2     string = "Test App 2"
	testInvalidPassword string = "weak"
	testClientID        string = "client-1234"
	testUserID          string = "user-1234"
	testClientSecret    string = "a-string-secret-at-least-256-bits-long-enough"
	testScope           string = "clients:manage users:manage"
	encodedTestScope    string = "client%3Amanage%20user%3Amanage"
	testRedirectURI     string = "https://vigiloauth.com/callback"
	testConsentApproved string = "true"
	testAuthzCode       string = "valid-auth-code"
	testIP              string = "192.168.1.10"
)

// VigiloTestContext encapsulates constants testing functionality across all test types
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
	secretKey          string
}

// NewVigiloTestContext creates a basic test context with default server configurations.
func NewVigiloTestContext(t *testing.T) *VigiloTestContext {
	privateKey, publicKey, secretKey, err := generateTestKeys()
	if err != nil {
		os.Exit(1)
	}

	config.GetServerConfig().Logger().SetLevel("debug")

	setEnvVariables(privateKey, publicKey, secretKey)
	return &VigiloTestContext{
		T:                  t,
		VigiloServer:       server.NewVigiloIdentityServer(),
		secretKey:          secretKey,
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
func (tc *VigiloTestContext) WithUser(scopes, roles []string) *VigiloTestContext {
	user := &users.User{
		ID:                  testUserID,
		Username:            testUsername,
		FullName:            testFirstName + " " + testMiddleName + " " + testFamilyName,
		FirstName:           testFirstName,
		MiddleName:          testMiddleName,
		FamilyName:          testFamilyName,
		Email:               testEmail,
		PhoneNumber:         testPhoneNumber,
		Password:            testPassword1,
		Birthdate:           testBirthdate,
		Gender:              testGender,
		Scopes:              scopes,
		Roles:               roles,
		LastFailedLogin:     time.Time{},
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		AccountLocked:       false,
		EmailVerified:       false,
		PhoneNumberVerified: true,
		Address: &users.UserAddress{
			Formatted:     testStreetAddress + ", " + testLocality + ", " + testRegion + ", " + testPostalCode + ", " + testCountry,
			StreetAddress: testStreetAddress,
			Locality:      testLocality,
			Region:        testRegion,
			PostalCode:    testPostalCode,
			Country:       testCountry,
		},
	}
	hashedPassword, err := crypto.HashString(user.Password)
	assert.NoError(tc.T, err)

	user.Password = hashedPassword
	userRepo.GetInMemoryUserRepository().AddUser(context.Background(), user)

	tc.User = user
	return tc
}

func (tc *VigiloTestContext) WithUserConsent() *VigiloTestContext {
	consentRepo.GetInMemoryUserConsentRepository().SaveConsent(context.Background(), testUserID, testClientID, testScope)
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
		ResponseTypes: []string{constants.CodeResponseType},
		RedirectURIS:  []string{testRedirectURI},
	}

	if clientType == client.Confidential {
		c.Secret = testClientSecret
	}

	clientRepo.GetInMemoryClientRepository().SaveClient(context.Background(), c)
}

// WithJWTToken creates and adds a user JWT token to the system.
func (tc *VigiloTestContext) WithJWTToken(id string, duration time.Duration) *VigiloTestContext {
	if tc.User == nil {
		tc.WithUser([]string{constants.UserManage}, []string{constants.AdminRole})
	}

	tokenService := tokenService.NewTokenService(tokenRepo.GetInMemoryTokenRepository())
	token, err := tokenService.GenerateToken(
		context.Background(), id, testScope,
		strings.Join(tc.User.Roles, " "), duration,
	)
	assert.NoError(tc.T, err)

	tc.JWTToken = token
	tokenRepo.GetInMemoryTokenRepository().SaveToken(context.Background(), token, id, time.Now().Add(duration))

	return tc
}

func (tc *VigiloTestContext) WithJWTTokenWithScopes(subject, audience string, scopes []string, duration time.Duration) *VigiloTestContext {
	if tc.User == nil {
		tc.WithUser([]string{constants.UserManage}, []string{constants.AdminRole})
	}

	tokenService := tokenService.NewTokenService(tokenRepo.GetInMemoryTokenRepository())
	accessToken, refreshToken, err := tokenService.GenerateTokensWithAudience(
		context.Background(), subject, audience, strings.Join(scopes, " "),
		strings.Join(tc.User.Roles, " "),
	)
	assert.NoError(tc.T, err)

	tc.JWTToken = accessToken
	tokenRepo.GetInMemoryTokenRepository().SaveToken(context.Background(), accessToken, subject, time.Now().Add(duration))
	tokenRepo.GetInMemoryTokenRepository().SaveToken(context.Background(), refreshToken, subject, time.Now().Add(duration))

	return tc
}

func (tc *VigiloTestContext) WithBlacklistedToken(id string) *VigiloTestContext {
	tokenService := tokenService.NewTokenService(tokenRepo.GetInMemoryTokenRepository())
	token, err := tokenService.GenerateToken(context.Background(), id, testScope, constants.AdminRole, config.GetServerConfig().TokenConfig().RefreshTokenDuration())
	assert.NoError(tc.T, err)

	tc.JWTToken = token
	tokenService.BlacklistToken(context.Background(), token)

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
			[]string{constants.ClientManage},
			[]string{constants.ClientCredentials},
		)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(testClientID + ":" + testClientSecret))
	formData := url.Values{}
	formData.Add(constants.GrantType, constants.ClientCredentials)
	formData.Add(constants.Scope, constants.ClientManage)

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
		tc.WithUser([]string{constants.UserManage}, []string{constants.AdminRole})
	}

	tokenService := tokenService.NewTokenService(tokenRepo.GetInMemoryTokenRepository())
	resetToken, err := tokenService.GenerateToken(context.Background(), tc.User.Email, testScope, constants.AdminRole, duration)
	assert.NoError(tc.T, err)

	tokenRepo.GetInMemoryTokenRepository().SaveToken(context.Background(), resetToken, tc.User.Email, time.Now().Add(duration))
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
	queryParams.Add(constants.ClientID, testClientID)
	queryParams.Add(constants.RedirectURI, testRedirectURI)
	// queryParams.Add(constants.State, state)
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
		tc.WithUser([]string{constants.UserManage}, []string{constants.AdminRole})
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
	queryParams.Add(constants.ClientID, testClientID)
	queryParams.Add(constants.RedirectURI, testRedirectURI)
	queryParams.Add(constants.Scope, testScope)
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

	authzCode := parsedURL.Query().Get(constants.CodeResponseType)
	assert.NotEmpty(tc.T, authzCode, "Authorization code should not be empty")

	return authzCode
}

func (tc *VigiloTestContext) CreateAuthorizationCodeRequestQueryParams(codeChallenge, codeChallengeMethod string) url.Values {
	queryParams := url.Values{}
	queryParams.Add(constants.ResponseType, constants.CodeResponseType)
	queryParams.Add(constants.ClientID, testClientID)
	queryParams.Add(constants.RedirectURI, testRedirectURI)
	queryParams.Add(constants.Scope, constants.ClientManage)
	queryParams.Add(constants.State, tc.State)
	queryParams.Add(constants.ConsentApprovedURLValue, "true")

	if codeChallenge != "" {
		queryParams.Add(constants.CodeChallenge, codeChallenge)
	}
	if codeChallengeMethod != "" {
		queryParams.Add(constants.CodeChallengeMethod, codeChallengeMethod)
	}

	return queryParams
}

func (tc *VigiloTestContext) GetAuthzCodeWithPKCE(codeChallenge, codeChallengeMethod string) string {
	queryParams := tc.CreateAuthorizationCodeRequestQueryParams(codeChallenge, codeChallengeMethod)
	parsedURL := tc.sendAuthorizationCodeRequest(queryParams)

	authzCode := parsedURL.Query().Get(constants.CodeURLValue)
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

func (tc *VigiloTestContext) WithDebugLogs() {
	config.GetServerConfig().Logger().SetLevel("DEBUG")
}

func (tc *VigiloTestContext) WithAuditEvents() {
	ctx := context.Background()
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserID, testUserID)
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyIPAddress, testIP)
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyRequestID, "req-"+crypto.GenerateUUID())
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeySessionID, "sess-"+crypto.GenerateUUID())
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyTokenClaims, tc.JWTToken)

	eventCount := 100
	for range eventCount {
		event := audit.NewAuditEvent(ctx, audit.LoginAttempt, false, audit.AuthenticationAction, audit.EmailMethod, errors.ErrCodeAccountLocked)
		err := auditEventRepo.GetInMemoryAuditEventRepository().StoreAuditEvent(ctx, event)
		assert.NoError(tc.T, err)
	}
}

func (tc *VigiloTestContext) GetUserRegistrationRequest() *users.UserRegistrationRequest {
	return &users.UserRegistrationRequest{
		Username:    testUsername,
		FirstName:   testFirstName,
		MiddleName:  testMiddleName,
		FamilyName:  testFamilyName,
		Birthdate:   testBirthdate,
		Email:       testEmail,
		Gender:      testGender,
		PhoneNumber: testPhoneNumber,
		Password:    testPassword1,
		Scopes:      []string{constants.UserManage},
		Roles:       []string{constants.AdminRole},
		Address: users.UserAddress{
			StreetAddress: testStreetAddress,
			Locality:      testLocality,
			Region:        testRegion,
			PostalCode:    testPostalCode,
			Country:       testCountry,
		},
	}
}

// TearDown performs cleanup operations.
func (tc *VigiloTestContext) TearDown() {
	if tc.TestServer != nil {
		tc.TestServer.Close()
	}
	tc.VigiloServer.Shutdown()
	config.GetServerConfig().Logger().SetLevel("info")
	clearEnvVariables()
	resetInMemoryStores()
}

func (tc *VigiloTestContext) sendAuthorizationCodeRequest(queryParams url.Values) *url.URL {
	endpoint := web.OAuthEndpoints.Authorize + "?" + queryParams.Encode()
	headers := map[string]string{"Cookie": tc.SessionCookie.Name + "=" + tc.SessionCookie.Value}

	rr := tc.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)
	assert.Equal(tc.T, http.StatusFound, rr.Code)

	location := rr.Header().Get(constants.RedirectLocationURLValue)
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
	auditEventRepo.ResetInMemoryAuditEventRepository()
}

func (tc *VigiloTestContext) decodeErrorResponse(rr *httptest.ResponseRecorder) errors.VigiloAuthError {
	var errResp errors.VigiloAuthError
	err := json.NewDecoder(rr.Body).Decode(&errResp)
	assert.NoError(tc.T, err, "Failed to unmarshal response body")
	return errResp
}

func getSecretKey() string {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key)
}

func generateTestKeys() (string, string, string, error) {
	privateKeyBase64 := os.Getenv(constants.TokenPrivateKeyENV)
	publicKeyBase64 := os.Getenv(constants.TokenPublicKeyENV)

	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		panic("Failed to decode private key: " + err.Error())
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		panic("Failed to decode public key: " + err.Error())
	}

	secretKey := getSecretKey()

	return string(privateKeyBytes), string(publicKeyBytes), secretKey, nil
}

func setEnvVariables(privateKey, publicKey, secretKey string) {
	os.Setenv(constants.CryptoSecretKeyENV, secretKey)
	os.Setenv(constants.SMTPUsernameENV, "fake@email")
	os.Setenv(constants.SMTPFromAddressENV, "fake@email")
	os.Setenv(constants.SMTPPasswordENV, "password")
	os.Setenv(constants.TokenIssuerENV, "fake-issuer")
	os.Setenv(constants.TokenPrivateKeyENV, privateKey)
	os.Setenv(constants.TokenPublicKeyENV, publicKey)

}

func clearEnvVariables() {
	os.Unsetenv(constants.CryptoSecretKeyENV)
	os.Unsetenv(constants.SMTPUsernameENV)
	os.Unsetenv(constants.SMTPFromAddressENV)
	os.Unsetenv(constants.SMTPPasswordENV)
	os.Unsetenv(constants.TokenIssuerENV)
	os.Unsetenv(constants.TokenPrivateKeyENV)
	os.Unsetenv(constants.TokenPublicKeyENV)
}
