package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/web"
)

func TestClientHandler_RegisterClient(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *client.ClientRegistrationRequest
		expectedStatus int
		isPublicClient bool
	}{
		{
			name:           "Successful Public Client Registration",
			requestBody:    createClientRegistrationRequest(),
			expectedStatus: http.StatusCreated,
			isPublicClient: true,
		},
		{
			name:           "Successful Confidential Client Registration",
			requestBody:    createClientRegistrationRequest(),
			expectedStatus: http.StatusCreated,
			isPublicClient: false,
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
			requestBody, err := json.Marshal(test.requestBody)
			assert.NoError(t, err)

			rr := testContext.SendHTTPRequest(
				http.MethodPost,
				web.ClientEndpoints.Registration,
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

			assert.NotEmpty(t, responseBody.ID)
			assert.Equal(t, test.requestBody.Name, responseBody.Name)
			assert.Equal(t, test.requestBody.Type, responseBody.Type)
			assert.ElementsMatch(t, test.requestBody.RedirectURIS, responseBody.RedirectURIS)
		})
	}
}

func TestClientHandler_RegisterClient_InvalidRequestFormat(t *testing.T) {
	req := []byte(`{invalid_json}`)
	testContext := NewVigiloTestContext(t)
	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Registration,
		bytes.NewReader(requestBody),
		nil,
	)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestClientHandler_RegisterClient_MissingRequiredFields(t *testing.T) {
	req := createClientRegistrationRequest()
	req.RedirectURIS = []string{}

	testContext := NewVigiloTestContext(t)
	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Registration,
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
	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Registration,
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
	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Registration,
		bytes.NewReader(requestBody),
		nil,
	)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_InvalidContentType(t *testing.T) {
	req := createClientRegistrationRequest()
	req.Type = client.Public

	testContext := NewVigiloTestContext(t)
	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	headers := map[string]string{"Content-Type": "text/plain"}

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Registration,
		bytes.NewReader(requestBody),
		headers,
	)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_RateLimitingExceeded(t *testing.T) {
	req := createClientRegistrationRequest()
	req.Type = client.Public

	maxRequests := 5
	testContext := NewVigiloTestContext(t).
		WithCustomConfig(config.WithMaxRequestsPerMinute(maxRequests))

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	// Requests should succeed
	for i := range maxRequests {
		rr := testContext.SendHTTPRequest(
			http.MethodPost,
			web.ClientEndpoints.Registration,
			bytes.NewReader(requestBody),
			nil,
		)
		assert.Equal(t, http.StatusCreated, rr.Code, "Request %d should succeed", i+1)
	}

	rr := testContext.SendHTTPRequest(
		http.MethodPost,
		web.ClientEndpoints.Registration,
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
	).WithClientCredentialsToken()

	endpoint := strings.Replace(web.ClientEndpoints.RegenerateSecret, "{client_id}", testClientID, 1)
	rr := testContext.SendHTTPRequest(http.MethodPost, endpoint, nil, nil)
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
	testContext.WithClient(
		client.Confidential,
		[]string{client.ClientManage},
		[]string{client.ClientCredentials},
	).WithClientCredentialsToken()

	endpoint := strings.Replace(web.ClientEndpoints.RegenerateSecret, "{client_id}", "", 1)
	rr := testContext.SendHTTPRequest(http.MethodPost, endpoint, nil, nil)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func createClientRegistrationRequest() *client.ClientRegistrationRequest {
	return &client.ClientRegistrationRequest{
		Name:          "Test Name",
		RedirectURIS:  []string{"https://loaclhost/callback"},
		GrantTypes:    []string{client.AuthorizationCode, client.PKCE},
		Scopes:        []string{client.ClientRead, client.ClientWrite},
		ResponseTypes: []client.ResponseType{client.CodeResponseType, client.IDTokenResponseType},
	}
}
