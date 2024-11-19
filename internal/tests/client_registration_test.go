/*
 * Copyright 2024 Olivier Pimpare-Charbonneau, Zachary Sexton
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tests

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/clients"
	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/internal/utils"
	"github.com/vigiloauth/vigilo/pkg/models"
	"github.com/vigiloauth/vigilo/pkg/server"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientRegistration(t *testing.T) {
	vigiloServer := server.NewVigiloServer()
	tests := []struct {
		name           string
		requestBody    models.ClientRegistrationRequest
		expectedStatus int
		expectSuccess  bool
		errorMessage   string
	}{
		{
			name: "Successful Registration",
			requestBody: models.ClientRegistrationRequest{
				Name:         "Test Client",
				RedirectURIs: []string{"https://valid.com/callback"},
				ClientType:   clients.Public,
				GrantTypes:   []clients.GrantType{clients.PKCE},
			},
			expectedStatus: http.StatusCreated,
			expectSuccess:  true,
		}, {
			name: "Invalid Client Name",
			requestBody: models.ClientRegistrationRequest{
				Name:         "",
				RedirectURIs: []string{"https://valid.com/callback"},
				ClientType:   clients.Public,
				GrantTypes:   []clients.GrantType{clients.PKCE},
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			errorMessage:   "name is required",
		}, {
			name: "Empty Redirect URIs",
			requestBody: models.ClientRegistrationRequest{
				Name:         "Test Client",
				RedirectURIs: []string{},
				ClientType:   clients.Public,
				GrantTypes:   []clients.GrantType{clients.PKCE},
			},
			expectedStatus: http.StatusBadRequest,
			expectSuccess:  false,
			errorMessage:   "redirect_uris is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jsonBody, err := json.Marshal(test.requestBody)
			assert.NoError(t, err, "Failed to marshal request body")

			req, err := http.NewRequest(
				http.MethodPost,
				constants.ClientRegistrationURL,
				bytes.NewBuffer(jsonBody),
			)

			assert.NoError(t, err, "Failed to create request")
			req.Header.Set("Content-Type", "application/json")

			responseRecorder := httptest.NewRecorder()
			handler := vigiloServer.Handler()
			handler.ServeHTTP(responseRecorder, req)

			assert.Equal(t, test.expectedStatus, responseRecorder.Code,
				"Expected status code %d but got %d",
				test.expectedStatus,
				responseRecorder.Code,
			)

			if test.expectSuccess {
				var response models.ClientRegistrationResponse
				err = json.Unmarshal(responseRecorder.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.NotEmpty(t, response.ClientID)
				assert.NotEmpty(t, response.ClientType)
				assert.Equal(t, test.requestBody.RedirectURIs, response.RedirectURIs)
				assert.Equal(t, test.requestBody.GrantTypes, response.GrantTypes)
				assert.NotEmpty(t, response.CreatedAt)
			} else {
				var errorResponse utils.ErrorResponse
				err = json.Unmarshal(responseRecorder.Body.Bytes(), &errorResponse)
				assert.NoError(t, err)
				assert.Contains(t, errorResponse.Description, test.errorMessage)
			}
		})
	}
}
