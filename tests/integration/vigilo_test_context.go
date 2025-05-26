package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/idp/server"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	service "github.com/vigiloauth/vigilo/v2/internal/service/crypto"
	jwtService "github.com/vigiloauth/vigilo/v2/internal/service/jwt"
	tokenService "github.com/vigiloauth/vigilo/v2/internal/service/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"

	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	userConsent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	auditEventRepo "github.com/vigiloauth/vigilo/v2/internal/repository/audit"
	sessionRepo "github.com/vigiloauth/vigilo/v2/internal/repository/session"
	tokenRepo "github.com/vigiloauth/vigilo/v2/internal/repository/token"
	consentRepo "github.com/vigiloauth/vigilo/v2/internal/repository/userconsent"

	"github.com/vigiloauth/vigilo/v2/internal/utils"

	"github.com/vigiloauth/vigilo/v2/internal/web"

	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	clientRepo "github.com/vigiloauth/vigilo/v2/internal/repository/client"
	userRepo "github.com/vigiloauth/vigilo/v2/internal/repository/user"
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
	testScope           string = "openid profile address"
	encodedTestScope    string = "client%3Amanage%20user%3Amanage"
	testRedirectURI     string = "https://vigiloauth.com/callback"
	testConsentApproved string = "true"
	testAuthzCode       string = "valid-auth-code"
	testIP              string = "192.168.1.10"
	testNonce           string = "123na"
	testState           string = "12345State"
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
	RequestURI         string
}

// NewVigiloTestContext creates a basic test context with default server configurations.
func NewVigiloTestContext(t *testing.T) *VigiloTestContext {
	config.GetServerConfig().Logger().SetLevel("debug")
	config.GetServerConfig().SetBaseURL("http://localhost")

	return &VigiloTestContext{
		T:                  t,
		VigiloServer:       server.NewVigiloIdentityServer(),
		SH256CodeChallenge: utils.EncodeSHA256(testClientSecret),

		PlainCodeChallenge: testClientSecret,
	}
}

// WithLiveServer adds a live test server to the context.
func (tc *VigiloTestContext) WithLiveHTTPServer() *VigiloTestContext {
	tc.TestServer = httptest.NewServer(tc.VigiloServer.Router())
	return tc
}

// WithUser creates and adds a user to the system.
func (tc *VigiloTestContext) WithUser(roles []string) *VigiloTestContext {
	user := &users.User{
		ID:                  testUserID,
		PreferredUsername:   testUsername,
		Name:                testFirstName + " " + testMiddleName + " " + testFamilyName,
		GivenName:           testFirstName,
		MiddleName:          testMiddleName,
		FamilyName:          testFamilyName,
		Email:               testEmail,
		PhoneNumber:         testPhoneNumber,
		Password:            testPassword1,
		Birthdate:           testBirthdate,
		Gender:              testGender,
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

	crypto := service.NewCryptographer()
	hashedPassword, err := crypto.HashString(user.Password)
	assert.NoError(tc.T, err)

	user.Password = hashedPassword
	userRepo.GetInMemoryUserRepository().AddUser(context.Background(), user)

	tc.User = user
	return tc
}

func (tc *VigiloTestContext) WithUserConsent() *VigiloTestContext {
	consentRepo.GetInMemoryUserConsentRepository().SaveConsent(context.Background(), testUserID, testClientID, types.CombineScopes(types.Scope(testScope)))
	return tc
}

// WithClient creates and adds a user to the system.
//
// Parameters:
//
// clientType client.ClientType: The type of client (public or confidential).
// scopes []client.Scope: An array of scopes.
// grantTypes []client.GrantType: An array of grantTypes.
func (tc *VigiloTestContext) WithClient(clientType types.ClientType, scopes []types.Scope, grantTypes []string) {
	c := &client.Client{
		Name:          testClientName1,
		ID:            testClientID,
		Type:          clientType,
		GrantTypes:    grantTypes,
		ResponseTypes: []string{constants.CodeResponseType},
		RedirectURIs:  []string{testRedirectURI},
	}

	if len(scopes) == 0 {
		c.CanRequestScopes = true
	} else {
		c.Scopes = scopes
	}

	if clientType == types.ConfidentialClient {
		c.Secret = testClientSecret
		c.ApplicationType = constants.WebApplicationType
		c.TokenEndpointAuthMethod = types.ClientSecretBasicTokenAuth
	} else if slices.Contains(grantTypes, constants.AuthorizationCodeGrantType) {
		c.RequiresPKCE = true
		c.ApplicationType = constants.NativeApplicationType
		c.TokenEndpointAuthMethod = types.NoTokenAuth
	}

	clientRepo.GetInMemoryClientRepository().SaveClient(context.Background(), c)
}

// WithJWTToken creates and adds a user JWT token to the system.
func (tc *VigiloTestContext) WithJWTToken(id string, duration time.Duration) *VigiloTestContext {
	if tc.User == nil {
		tc.WithUser([]string{constants.AdminRole})
	}

	repo := tokenRepo.GetInMemoryTokenRepository()
	cryptoService := service.NewCryptographer()
	jwt := jwtService.NewJWTService()

	creator := tokenService.NewTokenCreator(repo, jwt, cryptoService)
	tokenService := tokenService.NewTokenIssuer(creator)
	token, err := tokenService.IssueAccessToken(
		context.Background(),
		id,
		testClientID,
		types.CombineScopes(types.Scope(testScope)),
		"", testNonce,
	)

	assert.NoError(tc.T, err)
	tc.JWTToken = token

	return tc
}

func (tc *VigiloTestContext) WithAdminToken(id string, duration time.Duration) *VigiloTestContext {
	if tc.User == nil {
		tc.WithUser([]string{constants.AdminRole})
	}

	repo := tokenRepo.GetInMemoryTokenRepository()
	cryptoService := service.NewCryptographer()
	jwt := jwtService.NewJWTService()

	creator := tokenService.NewTokenCreator(repo, jwt, cryptoService)
	tokenService := tokenService.NewTokenIssuer(creator)
	token, err := tokenService.IssueAccessToken(
		context.Background(),
		testUserID,
		testClientID,
		types.CombineScopes(types.Scope(testScope)),
		constants.AdminRole, testNonce,
	)

	assert.NoError(tc.T, err)
	tc.JWTToken = token

	return tc
}

func (tc *VigiloTestContext) WithJWTTokenWithScopes(subject, audience string, scopes []types.Scope, duration time.Duration) *VigiloTestContext {
	if tc.User == nil {
		tc.WithUser([]string{constants.AdminRole})
	}

	if len(scopes) == 0 {
		scopes = append(scopes, types.OpenIDScope)
	}

	repo := tokenRepo.GetInMemoryTokenRepository()
	cryptoService := service.NewCryptographer()
	jwt := jwtService.NewJWTService()

	creator := tokenService.NewTokenCreator(repo, jwt, cryptoService)
	tokenService := tokenService.NewTokenIssuer(creator)
	accessToken, err := tokenService.IssueAccessToken(
		context.Background(),
		testUserID,
		testClientID,
		types.NewScopeList(scopes...),
		"", testNonce,
	)
	assert.NoError(tc.T, err)
	tc.JWTToken = accessToken

	return tc
}

func (tc *VigiloTestContext) WithJWTTokenWithClaims(subject, audience string, claims *domain.ClaimsRequest) *VigiloTestContext {
	if tc.User == nil {
		tc.WithUser([]string{constants.AdminRole})
	}

	repo := tokenRepo.GetInMemoryTokenRepository()
	cryptoService := service.NewCryptographer()
	jwt := jwtService.NewJWTService()

	creator := tokenService.NewTokenCreator(repo, jwt, cryptoService)
	tokenService := tokenService.NewTokenIssuer(creator)
	accessToken, _, err := tokenService.IssueTokenPair(
		context.Background(),
		testUserID,
		testClientID,
		types.OpenIDScope,
		"", testNonce,
		claims,
	)

	assert.NoError(tc.T, err)
	tc.JWTToken = accessToken

	return tc
}

func (tc *VigiloTestContext) WithBlacklistedToken(id string) *VigiloTestContext {
	repo := tokenRepo.GetInMemoryTokenRepository()
	cryptoService := service.NewCryptographer()
	jwt := jwtService.NewJWTService()

	creator := tokenService.NewTokenCreator(repo, jwt, cryptoService)
	issuer := tokenService.NewTokenIssuer(creator)
	token, err := issuer.IssueAccessToken(
		context.Background(),
		testUserID,
		testClientID,
		types.CombineScopes(types.Scope(testScope)),
		"", testNonce,
	)

	assert.NoError(tc.T, err)
	tc.JWTToken = token

	parser := tokenService.NewTokenParser(jwt)
	validator := tokenService.NewTokenValidator(repo, parser)

	manager := tokenService.NewTokenManager(repo, parser, validator)
	manager.BlacklistToken(context.Background(), token)

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
			types.ConfidentialClient,
			[]types.Scope{types.OpenIDScope},
			[]string{constants.ClientCredentialsGrantType},
		)
	}

	auth := base64.StdEncoding.EncodeToString([]byte(testClientID + ":" + testClientSecret))
	formData := url.Values{}
	formData.Add(constants.GrantTypeReqField, constants.ClientCredentialsGrantType)
	formData.Add(constants.ScopeReqField, types.OpenIDScope.String())

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
	return tc.WithJWTToken(testUserID, -10*time.Hour)
}

// WithPasswordResetToken generates a password reset token.
func (tc *VigiloTestContext) WithPasswordResetToken(duration time.Duration) (string, *VigiloTestContext) {
	if tc.User == nil {
		tc.WithUser([]string{constants.AdminRole})
	}

	repo := tokenRepo.GetInMemoryTokenRepository()
	cryptoService := service.NewCryptographer()
	jwt := jwtService.NewJWTService()

	creator := tokenService.NewTokenCreator(repo, jwt, cryptoService)
	issuer := tokenService.NewTokenIssuer(creator)
	token, err := issuer.IssueAccessToken(
		context.Background(),
		testUserID,
		testClientID,
		types.CombineScopes(types.Scope(testScope)),
		"", testNonce,
	)

	assert.NoError(tc.T, err)
	return token, tc
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
		Username: testUsername,
		Password: testPassword1,
	}

	requestBody, err := json.Marshal(loginRequest)
	assert.NoError(tc.T, err)

	state := tc.GetStateFromSession()
	tc.State = state

	queryParams := url.Values{}
	queryParams.Add(constants.ClientIDReqField, testClientID)
	queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
	endpoint := web.OAuthEndpoints.Authenticate + "?" + queryParams.Encode()

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
		tc.WithUser([]string{constants.AdminRole})
	}

	loginRequest := users.NewUserLoginRequest(testUsername, testPassword1)
	body, err := json.Marshal(loginRequest)
	assert.NoError(tc.T, err)

	rr := tc.SendHTTPRequest(
		http.MethodPost,
		web.OAuthEndpoints.Authenticate,
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
	queryParams.Add(constants.ClientIDReqField, testClientID)
	queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
	queryParams.Add(constants.ScopeReqField, testScope)
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
	queryParams.Add(constants.ResponseTypeReqField, constants.CodeResponseType)
	queryParams.Add(constants.ClientIDReqField, testClientID)
	queryParams.Add(constants.RedirectURIReqField, testRedirectURI)
	queryParams.Add(constants.ScopeReqField, "openid profile")
	queryParams.Add(constants.StateReqField, tc.State)
	queryParams.Add(constants.ConsentApprovedURLValue, "true")
	queryParams.Add(constants.NonceReqField, testNonce)
	queryParams.Add("acr_values", "1 2")

	if codeChallenge != "" {
		queryParams.Add(constants.CodeChallengeReqField, codeChallenge)
	}
	if codeChallengeMethod != "" {
		queryParams.Add(constants.CodeChallengeMethodReqField, codeChallengeMethod)
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
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyRequestID, "req-"+utils.GenerateUUID())
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeySessionID, "sess-"+utils.GenerateUUID())
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
	config.GetServerConfig().Logger().SetLevel("info")
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

func GenerateHeaderWithCredentials(id, secret string) map[string]string {
	headers := map[string]string{
		"Content-Type":  "application/x-www-form-urlencoded",
		"Authorization": "Basic " + encodeClientCredentials(id, secret),
	}

	return headers
}

func encodeClientCredentials(clientID, clientSecret string) string {
	return base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
}
