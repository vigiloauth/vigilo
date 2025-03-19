package integration_tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/internal/client"
	"github.com/vigiloauth/vigilo/internal/utils"
)

func setupTest(requestBody []byte) *httptest.ResponseRecorder {
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	req := httptest.NewRequest(http.MethodPost, utils.ClientEndpoints.Registration, bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)
	return rr
}

func TestClientHandler_RegisterClient(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    *client.ClientRegistrationRequest
		expectedStatus int
		wantError      bool
		isPublicClient bool
	}{
		{
			name:           "Successful Public Client Registration",
			requestBody:    createClientRegistrationRequest(),
			expectedStatus: http.StatusCreated,
			wantError:      false,
			isPublicClient: true,
		},
		{
			name:           "Successful Confidential Client Registration",
			requestBody:    createClientRegistrationRequest(),
			expectedStatus: http.StatusCreated,
			wantError:      false,
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

			requestBody, err := json.Marshal(test.requestBody)
			assert.NoError(t, err)

			rr := setupTest(requestBody)
			assert.Equal(t, test.expectedStatus, rr.Code)

			if test.wantError {
				checkErrorResponse(t, rr.Body.Bytes())
			} else {
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
			}
		})
	}
}

func TestClientHandler_RegisterClient_InvalidRequestFormat(t *testing.T) {
	req := []byte(`{invalid_json}`)
	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := setupTest(requestBody)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

func TestClientHandler_RegisterClient_MissingRequiredFields(t *testing.T) {
	req := createClientRegistrationRequest()
	req.RedirectURIS = []string{}

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := setupTest(requestBody)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_InvalidRedirectURIS(t *testing.T) {
	req := createClientRegistrationRequest()
	req.RedirectURIS = []string{"not-a-valid-url"}

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := setupTest(requestBody)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_InvalidGrantTypes(t *testing.T) {
	req := createClientRegistrationRequest()
	req.GrantTypes = []client.GrantType{"invalid-grant"}

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	rr := setupTest(requestBody)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_InvalidContentType(t *testing.T) {
	request := createClientRegistrationRequest()
	request.Type = client.Public

	requestBody, err := json.Marshal(request)
	assert.NoError(t, err)

	vigiloIdentityServer := server.NewVigiloIdentityServer()
	req := httptest.NewRequest(http.MethodPost, utils.ClientEndpoints.Registration, bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	vigiloIdentityServer.Router().ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestClientHandler_RegisterClient_RateLimitingExceeded(t *testing.T) {
	maxRequests := 5
	config.NewServerConfig(config.WithMaxRequestsPerMinute(maxRequests))
	vigiloIdentityServer := server.NewVigiloIdentityServer()

	req := createClientRegistrationRequest()
	req.Type = client.Public

	requestBody, err := json.Marshal(req)
	assert.NoError(t, err)

	// Requests should succeed
	for i := range maxRequests {
		rr := sendRequest(vigiloIdentityServer, requestBody)
		assert.Equal(t, http.StatusCreated, rr.Code, "Request %d should succeed", i+1)
	}

	rr := sendRequest(vigiloIdentityServer, requestBody)
	assert.Equal(t, http.StatusTooManyRequests, rr.Code, "Request should be rate limited")
}

func sendRequest(server *server.VigiloIdentityServer, requestBody []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, utils.ClientEndpoints.Registration, bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	server.Router().ServeHTTP(rr, req)
	return rr
}

func createClientRegistrationRequest() *client.ClientRegistrationRequest {
	return &client.ClientRegistrationRequest{
		Name:          "Test Name",
		RedirectURIS:  []string{"https://loaclhost/callback"},
		GrantTypes:    []client.GrantType{client.AuthorizationCode, client.PKCE},
		Scopes:        []client.Scope{client.Read, client.Write},
		ResponseTypes: []client.ResponseType{client.CodeResponseType, client.IDTokenResponseType},
	}
}
