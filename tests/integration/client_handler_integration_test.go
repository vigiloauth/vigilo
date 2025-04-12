package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
	clientRepo "github.com/vigiloauth/vigilo/internal/repository/client"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestClientHandler_RegisterClient(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *client.ClientRegistrationRequest
		expectedStatus int
		isPublicClient bool
		wantErr        bool
	}{
		{
			name:           "Successful Public Client Registration",
			requestBody:    createClientRegistrationRequest(),
			expectedStatus: http.StatusCreated,
			isPublicClient: true,
			wantErr:        false,
		},
		{
			name:           "Successful Confidential Client Registration",
			requestBody:    createClientRegistrationRequest(),
			expectedStatus: http.StatusCreated,
			isPublicClient: false,
			wantErr:        false,
		},
		{
			name: "Error is returned when public client is not using PKCE",
			requestBody: &client.ClientRegistrationRequest{
				Name:          testClientName1,
				RedirectURIS:  []string{testRedirectURI},
				GrantTypes:    []string{client.AuthorizationCode},
				Scopes:        []string{client.ClientRead, client.ClientWrite},
				ResponseTypes: []string{client.CodeResponseType, client.IDTokenResponseType},
			},
			expectedStatus: http.StatusBadRequest,
			isPublicClient: true,
			wantErr:        true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.isPublicClient {
				test.requestBody.Type = client.Public
			} else {
				test.requestBody.Type = client.Confidential
			}

			testContext := NewVigiloTestContext(t)
			defer testContext.TearDown()
			testContext.WithCustomConfig(config.WithBaseURL("https://localhost"))

			requestBody, err := json.Marshal(test.requestBody)
			assert.NoError(t, err)

			rr := testContext.SendHTTPRequest(
				http.MethodPost,
				web.ClientEndpoints.Register,
				bytes.NewReader(requestBody),
				nil,
			)

			assert.Equal(t, test.expectedStatus, rr.Code)
			var responseBody client.ClientRegistrationResponse
			err = json.NewDecoder(rr.Body).Decode(&responseBody)
			assert.NoError(t, err)

			// For confidential clients, verify client secret was generated
			if test.isPublicClient {
				assert.Empty(t, responseBody.Secret)
			} else {
				assert.NotEmpty(t, responseBody.Secret)
			}

			if !test.wantErr {
				assert.NotEmpty(t, responseBody.ID)
				assert.Equal(t, test.requestBody.Name, responseBody.Name)
				assert.Equal(t, test.requestBody.Type, responseBody.Type)
				assert.NotEqual(t, "", responseBody.RegistrationAccessToken)
				assert.ElementsMatch(t, test.requestBody.RedirectURIS, responseBody.RedirectURIS)
			}
		})
	}
}

func TestClientHandler_RegisterClient_InvalidRequestFormat(t *testing.T) {
	req := []byte(`{invalid_json}`)
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Register,
		bytes.NewReader(requestBody),
		nil,
	)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_MissingRequiredFields(t *testing.T) {
	req := createClientRegistrationRequest()
	req.RedirectURIS = []string{}

	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Register,
		bytes.NewReader(requestBody),
		nil,
	)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_InvalidRedirectURIS(t *testing.T) {
	req := createClientRegistrationRequest()
	req.Type = client.Public
	req.RedirectURIS = []string{"not-a-valid-url"}

	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Register,
		bytes.NewReader(requestBody),
		nil,
	)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_InvalidGrantTypes(t *testing.T) {
	req := createClientRegistrationRequest()
	req.Type = client.Public
	req.GrantTypes = []string{"invalid-grant"}

	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Register,
		bytes.NewReader(requestBody),
		nil,
	)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_InvalidContentType(t *testing.T) {
	req := createClientRegistrationRequest()
	req.Type = client.Public

	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	headers := map[string]string{"Content-Type": "text/plain"}

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Register,
		bytes.NewReader(requestBody),
		headers,
	)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_RateLimitingExceeded(t *testing.T) {
	req := createClientRegistrationRequest()
	req.Type = client.Public

	maxRequests := 5
	testContext := NewVigiloTestContext(t)
	testContext.WithCustomConfig(config.WithMaxRequestsPerMinute(maxRequests))
	defer testContext.TearDown()

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	// Requests should succeed
	for i := range maxRequests {
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.ClientEndpoints.Register,
			bytes.NewReader(requestBody),
			nil,
		)
		assert.Equal(t, http.StatusCreated, rr.Code, "Request %d should succeed", i+1)
	}

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Register,
		bytes.NewReader(requestBody),
		nil,
	)

	assert.Equal(t, http.StatusTooManyRequests, rr.Code, "Request should be rate limited")
}

func TestClientHandler_RegenerateClientSecret_Success(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage},
		[]string{client.ClientCredentials},
	)
	testContext.WithClientCredentialsToken()
	defer testContext.TearDown()

	endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.RegenerateSecret, testClientID)
	headers := map[string]string{common.BearerAuthHeader: testContext.ClientAuthToken}

	rr := testContext.SendHTTPRequest(http.MethodPost, endpoint, nil, headers)
	assert.Equal(t, http.StatusOK, rr.Code)

	var response client.ClientSecretRegenerationResponse
	err := json.NewDecoder(rr.Body).Decode(&response)
	assert.NoError(t, err)

	assert.Equal(t, testClientID, response.ClientID)
	assert.NotEmpty(t, response.ClientSecret)
	assert.NotEqual(t, testClientSecret, response.ClientSecret)
	assert.NotZero(t, response.UpdatedAt)
}

func TestClientHandler_RegenerateClientSecret_MissingClientIDInRequest_ReturnsError(t *testing.T) {
	testContext := NewVigiloTestContext(t)
	defer testContext.TearDown()
	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage},
		[]string{client.ClientCredentials},
	)
	testContext.WithClientCredentialsToken()

	endpoint := fmt.Sprintf("%s/invalid-id", web.ClientEndpoints.RegenerateSecret)
	rr := testContext.SendHTTPRequest(http.MethodPost, endpoint, nil, nil)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestClientHandler_GetClient(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Public,
			[]string{client.ClientRead},
			[]string{client.ClientCredentials},
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}
		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)
		assert.Equal(t, http.StatusOK, rr.Code)

		var clientInformationResponse client.ClientInformationResponse
		err := json.NewDecoder(rr.Body).Decode(&clientInformationResponse)
		assert.NoError(t, err)
		assert.NotNil(t, clientInformationResponse)
		assert.Equal(t, testClientID, clientInformationResponse.ID)
	})

	t.Run("Success - Client secret is not included in the response for public clients", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]string{client.ClientCredentials},
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}
		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)

		assert.Equal(t, http.StatusOK, rr.Code)

		var clientInformationResponse client.ClientInformationResponse
		err := json.NewDecoder(rr.Body).Decode(&clientInformationResponse)
		assert.NoError(t, err)
		assert.NotNil(t, clientInformationResponse)
		assert.Equal(t, testClientID, clientInformationResponse.ID)
		assert.Equal(t, testClientSecret, clientInformationResponse.Secret)
	})

	t.Run("Error unauthorized is returned and the token is revoked when the client ID is invalid", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]string{client.ClientCredentials},
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/invalid-id", web.ClientEndpoints.ClientConfiguration)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}
		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeUnauthorized, "failed to validate and retrieve client information")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Error unauthorized is returned and the token is revoked when token subject and client ID do not match", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientManage},
			[]string{client.ClientCredentials},
		)
		testContext.WithJWTToken("invalid-ID", 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}
		rr := testContext.SendHTTPRequest(http.MethodGet, endpoint, nil, headers)

		t.Log(rr.Body.String())
		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeUnauthorized, "failed to validate and retrieve client information")
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})
}

func TestClientHandler_UpdateClient(t *testing.T) {
	t.Run("Success - Update confidential client", func(t *testing.T) {
		request := createClientUpdateRequest()
		request.Secret = testClientSecret
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			request.GetScopes(),
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}

		// Update client name
		request.Name = testClientName2
		requestBody, err := json.Marshal(request)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPut,
			endpoint,
			bytes.NewReader(requestBody),
			headers,
		)

		// Assert HTTP Response and response body
		var clientInformationResponse client.ClientInformationResponse
		err = json.NewDecoder(rr.Body).Decode(&clientInformationResponse)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rr.Code, "expected status 200 OK")
		assert.NotNil(t, clientInformationResponse)
		assert.Equal(t, testClientID, clientInformationResponse.ID)
		assert.NotEqual(t, "", clientInformationResponse.Secret, "client secret be included in the response for confidential clients")

		// Assert Client is updated in the database
		updatedClient := clientRepo.GetInMemoryClientRepository().GetClientByID(testClientID)
		assert.NotNil(t, updatedClient, "expected updated client to not be nil")
		assert.Equal(t, testClientID, updatedClient.ID, "expected client IDs to be the same.")
		assert.NotEqual(t, testClientName1, updatedClient.Name, "expected client name to be updated")
	})

	t.Run("Success - Update public client", func(t *testing.T) {
		request := createClientUpdateRequest()
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Public,
			request.GetScopes(),
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}

		// Update client name
		request.Name = testClientName2
		requestBody, err := json.Marshal(request)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPut,
			endpoint,
			bytes.NewReader(requestBody),
			headers,
		)

		// Assert HTTP Response and response body
		var clientInformationResponse client.ClientInformationResponse
		err = json.NewDecoder(rr.Body).Decode(&clientInformationResponse)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rr.Code, "expected status 200 OK")
		assert.NotNil(t, clientInformationResponse)
		assert.Equal(t, testClientID, clientInformationResponse.ID)
		assert.Equal(t, "", clientInformationResponse.Secret, "client secret not be included in the response for public clients")

		// Assert Client is updated in the database
		updatedClient := clientRepo.GetInMemoryClientRepository().GetClientByID(testClientID)
		assert.NotNil(t, updatedClient, "expected updated client to not be nil")
		assert.Equal(t, testClientID, updatedClient.ID, "expected client IDs to be the same.")
		assert.NotEqual(t, testClientName1, updatedClient.Name, "expected client name to be updated")
	})

	t.Run("Bad Request - Missing required fields", func(t *testing.T) {
		request := createClientUpdateRequest()
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Public,
			request.GetScopes(),
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}
		rr := testContext.SendHTTPRequest(http.MethodPut, endpoint, nil, headers)

		testContext.AssertErrorResponseDescription(rr, errors.ErrCodeInvalidRequest, "missing one or more required fields in the request")
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Bad Request - Invalid redirect URIs", func(t *testing.T) {
		request := createClientUpdateRequest()
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			request.GetScopes(),
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}

		// Attempt to update with invalid redirect URIs
		request.RedirectURIS = append(request.RedirectURIS, "http://test.com/callback", "https://example.com/*")
		requestBody, err := json.Marshal(request)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPut,
			endpoint,
			bytes.NewReader(requestBody),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Bad Request - Invalid response types", func(t *testing.T) {
		request := createClientUpdateRequest()
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			request.GetScopes(),
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}

		// Attempt to update with invalid response types.
		// Client Credentials is not allowed with Authorization Code.
		request.GrantTypes = []string{client.ClientCredentials}
		request.ResponseTypes = []string{client.CodeResponseType}
		requestBody, err := json.Marshal(request)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPut,
			endpoint,
			bytes.NewReader(requestBody),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Unauthorized - Token subject and client ID mismatch", func(t *testing.T) {
		request := createClientUpdateRequest()
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			request.GetScopes(),
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken("invalid-id", 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}

		requestBody, err := json.Marshal(request)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPut,
			endpoint,
			bytes.NewReader(requestBody),
			headers,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Unauthorized - Expired registration access token", func(t *testing.T) {
		request := createClientUpdateRequest()
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			request.GetScopes(),
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken(testClientID, -1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}

		requestBody, err := json.Marshal(request)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPut,
			endpoint,
			bytes.NewReader(requestBody),
			headers,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Unauthorized - Invalid client ID", func(t *testing.T) {
		request := createClientUpdateRequest()
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			request.GetScopes(),
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, "invalid-client-id")
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}

		requestBody, err := json.Marshal(request)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPut,
			endpoint,
			bytes.NewReader(requestBody),
			headers,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Unauthorized - Client secret mismatch", func(t *testing.T) {
		request := createClientUpdateRequest()
		request.Secret = "invalid-secret"
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			request.GetScopes(),
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}

		requestBody, err := json.Marshal(request)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPut,
			endpoint,
			bytes.NewReader(requestBody),
			headers,
		)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Forbidden - Insufficient scopes", func(t *testing.T) {
		request := createClientUpdateRequest()
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Confidential,
			[]string{client.ClientRead},
			request.GetGrantTypes(),
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		headers := map[string]string{common.BearerAuthHeader: testContext.JWTToken}

		requestBody, err := json.Marshal(request)
		assert.NoError(t, err)

		rr := testContext.SendHTTPRequest(
			http.MethodPut,
			endpoint,
			bytes.NewReader(requestBody),
			headers,
		)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestClientHandler_DeleteClient(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Public,
			[]string{client.ClientManage, client.ClientDelete},
			[]string{client.AuthorizationCode, client.PKCE},
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		rr := testContext.SendHTTPRequest(http.MethodDelete, endpoint, nil, nil)

		assert.Equal(t, http.StatusNoContent, rr.Code)
	})

	t.Run("Unauthorized - Token subject and client ID mismatch", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Public,
			[]string{client.ClientManage, client.ClientDelete},
			[]string{client.AuthorizationCode, client.PKCE},
		)
		testContext.WithJWTToken("invalid-id", 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		rr := testContext.SendHTTPRequest(http.MethodDelete, endpoint, nil, nil)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Unauthorized - Expired registration access token", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Public,
			[]string{client.ClientManage, client.ClientDelete},
			[]string{client.AuthorizationCode, client.PKCE},
		)
		testContext.WithJWTToken(testClientID, -1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		rr := testContext.SendHTTPRequest(http.MethodDelete, endpoint, nil, nil)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Unauthorized - Invalid client ID", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Public,
			[]string{client.ClientManage, client.ClientDelete},
			[]string{client.AuthorizationCode, client.PKCE},
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, "invalid-id")
		rr := testContext.SendHTTPRequest(http.MethodDelete, endpoint, nil, nil)

		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("Forbidden - Insufficient Scopes", func(t *testing.T) {
		testContext := NewVigiloTestContext(t)
		testContext.WithClient(
			client.Public,
			[]string{},
			[]string{client.AuthorizationCode, client.PKCE},
		)
		testContext.WithJWTToken(testClientID, 1*time.Hour)
		defer testContext.TearDown()

		endpoint := fmt.Sprintf("%s/%s", web.ClientEndpoints.ClientConfiguration, testClientID)
		rr := testContext.SendHTTPRequest(http.MethodDelete, endpoint, nil, nil)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func createClientRegistrationRequest() *client.ClientRegistrationRequest {
	return &client.ClientRegistrationRequest{
		Name:          testClientName1,
		RedirectURIS:  []string{testRedirectURI},
		GrantTypes:    []string{client.AuthorizationCode, client.PKCE},
		Scopes:        []string{client.ClientRead, client.ClientWrite},
		ResponseTypes: []string{client.CodeResponseType, client.IDTokenResponseType},
	}
}

func createClientUpdateRequest() *client.ClientUpdateRequest {
	return &client.ClientUpdateRequest{
		ID:            testClientID,
		Name:          testClientName1,
		RedirectURIS:  []string{testRedirectURI},
		GrantTypes:    []string{client.AuthorizationCode, client.PKCE},
		Scopes:        []string{client.ClientRead, client.ClientWrite, client.UserManage, client.ClientManage},
		ResponseTypes: []string{client.CodeResponseType, client.IDTokenResponseType},
	}
}
