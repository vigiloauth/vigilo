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

package services

import (
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/mocks"
	"github.com/vigiloauth/vigilo/internal/models"
	"strings"
	"testing"
)

func setupTest() (*mocks.MockClientRepository, *RegistrationService) {
	mockRepo := &mocks.MockClientRepository{}
	clientRegistration := NewRegistrationService(mockRepo)

	return mockRepo, clientRegistration
}

func TestRegisterClient_ValidData(t *testing.T) {
	mockRepo, clientRegistration := setupTest()
	client := createClient()

	mockRepo.On("Create", client).Return(nil)

	err := clientRegistration.RegisterClient(client)
	assert.NoError(t, err, "Expected no error when registering a valid client")

	mockRepo.On("FindById", client.ID).Return(client, nil)
	storedClient, err := mockRepo.FindById(client.ID)

	assert.NoError(t, err, "Expected no error when fetching a client by ID")
	assert.Equal(t, client, storedClient, "Expected the registered client to be returned")
}

func TestRegisterClient_RedirectURIsValidation(t *testing.T) {
	tests := []struct {
		name          string
		redirectURIs  []string
		expectedError bool
		errorMessage  string
	}{
		{
			name:          "ValidHTTPSRedirectURI",
			redirectURIs:  []string{"https://example.com/callback"},
			expectedError: false,
		}, {
			name:          "RedirectURIUsingHTTP",
			redirectURIs:  []string{"http://not.using.https.com/callback"},
			expectedError: true,
			errorMessage:  "scheme must be HTTPS",
		}, {
			name:          "EmptyHostName",
			redirectURIs:  []string{"https:///callback"},
			expectedError: true,
			errorMessage:  "host name cannot be empty",
		}, {
			name:          "URIHasFragment",
			redirectURIs:  []string{"https://example.com/callback#fragment"},
			expectedError: true,
			errorMessage:  "fragments are not allowed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRedirectURIs(&test.redirectURIs)
			if (err != nil) != test.expectedError {
				t.Errorf("unexpected error status: got %v, want %v", err != nil, test.expectedError)
			}
			if test.expectedError && err != nil && !strings.Contains(err.Error(), test.errorMessage) {
				t.Errorf("unexpected error message: got %v, want %v", err.Error(), test.errorMessage)
			}
		})
	}
}

func createClient() *models.Client {
	return models.NewClient(
		"My Client App",
		[]models.GrantTypeEnum{models.AuthorizationCode},
		[]string{"https://myclientapp.com/callback"},
		models.Confidential,
	)
}
