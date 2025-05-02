package integration

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	clients "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	jwk "github.com/vigiloauth/vigilo/v2/internal/domain/jwks"
	oidc "github.com/vigiloauth/vigilo/v2/internal/domain/oidc"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"

	"github.com/vigiloauth/vigilo/v2/internal/web"
)

func TestOIDCHandler_UserInfo(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name            string
			scopes          []string
			wantUserSession bool
		}{
			{
				name:            "Success with all scopes",
				scopes:          []string{constants.OpenIDScope, constants.UserProfileScope, constants.UserEmailScope, constants.UserPhoneScope, constants.UserAddressScope},
				wantUserSession: true,
			},
			{
				name:            "Success with offline access scope",
				scopes:          []string{constants.OpenIDScope, constants.UserProfileScope, constants.UserEmailScope, constants.UserPhoneScope, constants.UserAddressScope, constants.UserOfflineAccessScope},
				wantUserSession: false,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithUser(test.scopes, []string{constants.UserRole})
				testContext.WithClient(clients.Confidential, test.scopes, []string{constants.AuthorizationCodeGrantType})
				testContext.WithJWTTokenWithScopes(testUserID, testClientID, test.scopes, time.Duration(5*time.Minute))

				headers := map[string]string{constants.AuthorizationHeader: constants.BearerAuthHeader + testContext.JWTToken}
				if test.wantUserSession {
					testContext.WithUserSession()
					headers["Cookie"] = testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value
				}

				rr := testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.UserInfo, nil, headers)
				t.Log("Response:", rr.Body.String())
				assert.Equal(t, http.StatusOK, rr.Code, "Expected HTTP status code 200 OK, got %d", rr.Code)
			})
		}
	})

	t.Run("Success with individual scopes only", func(t *testing.T) {
		tests := []struct {
			name   string
			scopes []string
		}{
			{
				name:   "Success with profile scope only",
				scopes: []string{constants.OpenIDScope, constants.UserProfileScope},
			},
			{
				name:   "Success with email scope only",
				scopes: []string{constants.OpenIDScope, constants.UserEmailScope},
			},
			{
				name:   "Success with phone scope only",
				scopes: []string{constants.OpenIDScope, constants.UserPhoneScope},
			},
			{
				name:   "Success with address scope only",
				scopes: []string{constants.OpenIDScope, constants.UserAddressScope},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				testContext := NewVigiloTestContext(t)
				defer testContext.TearDown()

				testContext.WithUser(test.scopes, []string{constants.UserRole})
				testContext.WithClient(clients.Confidential, test.scopes, []string{constants.AuthorizationCodeGrantType})
				testContext.WithJWTTokenWithScopes(testUserID, testClientID, test.scopes, time.Duration(5*time.Minute))
				testContext.WithUserSession()

				headers := map[string]string{
					constants.AuthorizationHeader: constants.BearerAuthHeader + testContext.JWTToken,
					"Cookie":                      testContext.SessionCookie.Name + "=" + testContext.SessionCookie.Value,
				}

				rr := testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.UserInfo, nil, headers)
				assert.Equal(t, http.StatusOK, rr.Code, "Expected HTTP status code 200 OK, got %d", rr.Code)

				var userInfo *users.UserInfoResponse
				err := json.Unmarshal(rr.Body.Bytes(), &userInfo)
				assert.NoError(t, err, "Expected no error unmarshalling user info response")

				assert.NotNil(t, userInfo, "Expected user info response to be not nil")
				assert.Equal(t, testUserID, userInfo.Sub, "Expected user ID to match the test user ID")

				switch test.scopes[1] {
				case constants.UserProfileScope:
					assert.NotEmpty(t, userInfo.Name, "Expected user name to be not empty")
					assert.NotEmpty(t, userInfo.Username, "Expected user username to be not empty")
					assert.NotEmpty(t, userInfo.FirstName, "Expected user first name to be not empty")
					assert.NotEmpty(t, userInfo.FamilyName, "Expected user family name to be not empty")
					assert.NotEmpty(t, userInfo.MiddleName, "Expected user middle name to be not empty")
					assert.NotEmpty(t, userInfo.Birthdate, "Expected user birthdate to be not empty")
					assert.NotEmpty(t, userInfo.UpdatedAt, "Expected user updated at to be not empty")
				case constants.UserEmailScope:
					assert.NotEmpty(t, userInfo.Email, "Expected user email to be not empty")
					assert.NotNil(t, userInfo.EmailVerified, "Expected user email verified to be not nil")
				case constants.UserPhoneScope:
					assert.NotEmpty(t, userInfo.PhoneNumber, "Expected user phone number to be not empty")
					assert.NotNil(t, userInfo.PhoneNumberVerified, "Expected user phone number verified to be not nil")
				case constants.UserAddressScope:
					assert.NotEmpty(t, userInfo.Address, "Expected user address to be not empty")
				}
			})
		}
	})

	t.Run("Unauthorized error is returned when authorization header is missing", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		scopes := []string{constants.OpenIDScope, constants.UserProfileScope, constants.UserOfflineAccessScope}

		testContext.WithUser(scopes, []string{constants.UserRole})
		testContext.WithClient(clients.Confidential, scopes, []string{constants.AuthorizationCodeGrantType})

		rr := testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.UserInfo, nil, nil)

		assert.Equal(t, http.StatusUnauthorized, rr.Code, "Expected HTTP status code 401 Unauthorized, got %d", rr.Code)
		assert.Contains(t, rr.Body.String(), "missing or invalid authorization header", "Expected error message for missing authorization header")
	})

	t.Run("Unauthorized error is returned when the token subject is invalid", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		scopes := []string{constants.OpenIDScope, constants.UserProfileScope, constants.UserOfflineAccessScope}
		testContext.WithClient(clients.Confidential, scopes, []string{constants.AuthorizationCodeGrantType})
		testContext.WithJWTTokenWithScopes("invalid-subject", testClientID, scopes, time.Duration(5*time.Minute))

		headers := map[string]string{constants.AuthorizationHeader: constants.BearerAuthHeader + testContext.JWTToken}
		rr := testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.UserInfo, nil, headers)

		assert.Equal(t, http.StatusUnauthorized, rr.Code, "Expected HTTP status code 401 Unauthorized, got %d", rr.Code)
		assert.Contains(t, rr.Body.String(), "invalid user credentials", "Expected error message for invalid token subject")
	})

	t.Run("Unauthorized error is returned when the token audience is invalid", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		scopes := []string{constants.OpenIDScope, constants.UserProfileScope, constants.UserOfflineAccessScope}
		testContext.WithUser(scopes, []string{constants.UserRole})
		testContext.WithJWTTokenWithScopes(testUserID, "invalid-audience", scopes, time.Duration(5*time.Minute))

		headers := map[string]string{constants.AuthorizationHeader: constants.BearerAuthHeader + testContext.JWTToken}
		rr := testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.UserInfo, nil, headers)

		assert.Equal(t, http.StatusUnauthorized, rr.Code, "Expected HTTP status code 401 Unauthorized, got %d", rr.Code)
		assert.Contains(t, rr.Body.String(), "invalid client credentials", "Expected error message for invalid token audience")
	})

	t.Run("Forbidden error is returned when the user does not have the requested scopes", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		defer testContext.TearDown()

		scopes := []string{constants.OpenIDScope, constants.UserProfileScope, constants.UserEmailScope}
		testContext.WithUser([]string{}, []string{constants.UserRole})
		testContext.WithClient(clients.Confidential, scopes, []string{constants.AuthorizationCodeGrantType})
		testContext.WithJWTTokenWithScopes(testUserID, testClientID, []string{constants.OpenIDScope}, time.Duration(5*time.Minute))

		headers := map[string]string{constants.AuthorizationHeader: constants.BearerAuthHeader + testContext.JWTToken}
		rr := testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.UserInfo, nil, headers)

		assert.Equal(t, http.StatusForbidden, rr.Code, "Expected HTTP status code 403 Forbidden, got %d", rr.Code)
		assert.Contains(t, rr.Body.String(), "insufficient_scope", "Expected error message for insufficient scope")
	})
}

func TestOIDCHandler_GetJWKS(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	rr := testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.JWKS, nil, nil)
	assert.Equal(t, http.StatusOK, rr.Code, "Expected the status to be 200 OK but got: %s", rr.Code)

	var response *jwk.Jwks
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err, "Failed to unmarshal response")

	assert.NotEmpty(t, response.Keys, "Expected JWKS keys to not be empty")
	assert.NotEmpty(t, response.Keys[0].Kty, "Expected Kty to not be empty")
	assert.NotEmpty(t, response.Keys[0].Kid, "Expected Kid to not be empty")
	assert.NotEmpty(t, response.Keys[0].Use, "Expected Use to not be empty")
	assert.NotEmpty(t, response.Keys[0].Alg, "Expected Alg to not be empty")
	assert.NotEmpty(t, response.Keys[0].N, "Expected modulus to not be empty")
	assert.NotEmpty(t, response.Keys[0].E, "Expected exponent to not be empty")
	assert.NotEmpty(t, response.Keys[0].Kty, "Expected Kty to not be empty")
}

func TestOIDCHandler_GetOpenIDConfiguration(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	rr := testContext.SendHTTPRequest(http.MethodGet, web.OIDCEndpoints.Discovery, nil, nil)
	assert.Equal(t, http.StatusOK, rr.Code, "Expected 200 OK but got: %d", rr.Code)

	var response *oidc.DiscoveryJSON
	err := json.Unmarshal(rr.Body.Bytes(), &response)
	assert.NoError(t, err, "Failed to unmarshal response")

	assert.NotEmpty(t, response.Issuer, "Expected Issuer to not be empty")
	assert.NotEmpty(t, response.AuthorizationEndpoint, "Expected authorization endpoint to not be empty")
	assert.NotEmpty(t, response.TokenEndpoint, "Expected token endpoint to not be empty")
}
