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
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/mocks"
	"github.com/vigiloauth/vigilo/internal/models"
	"testing"
)

func setupTest(t *testing.T) (*mocks.InMemoryMockDB, *RegistrationService) {
	mockDB := mocks.NewInMemoryMockDB()
	clientRegistration := NewRegistrationService(mockDB)
	t.Cleanup(func() { mockDB.Reset() })

	return mockDB, clientRegistration
}

func TestRegisterClient_ValidData(t *testing.T) {
	mockDB, clientRegistration := setupTest(t)
	client := createClient()

	err := clientRegistration.RegisterClient(client)
	_, err = mockDB.Read(client.ID)

	assert.NoError(t, err, "Expected no error when registering a valid client")
	assert.NoError(t, err, "Expected client to be in the database after registration")
}

func TestRegisterClient_RedirectURIUsingHttp(t *testing.T) {
	mockDB, clientRegistration := setupTest(t)
	client := createClient()
	client.RedirectURIs = append(client.RedirectURIs, "http://invalid-uri.com/callback")

	err := clientRegistration.RegisterClient(client)
	assert.Error(t, err, "Expected error for non-HTTPS redirect URI")
	assert.Contains(t, err.Error(), "scheme must be HTTPS", "Expected specific error message about HTTPS scheme")

	_, err = mockDB.Read(client.ID)
	assert.Error(t, err, "Expected error when reading client from the database")
}

func TestRegisterClient_EmptyRedirectURIs(t *testing.T) {
	mockDB, clientRegistration := setupTest(t)
	client := createClient()
	client.RedirectURIs = []string{}

	err := clientRegistration.RegisterClient(client)

	assert.Error(t, err, "Expected error for empty redirect URIs")
	assert.Contains(t, err.Error(), "redirect URIs cannot be null", "Expected specific error message about empty redirect URIs")

	_, err = mockDB.Read(client.ID)
	assert.Error(t, err, "Expected error when reading client from the database")
}

func TestRegisterClient_MalformedRedirectURI(t *testing.T) {
	mockDB, clientRegistration := setupTest(t)
	client := createClient()
	client.RedirectURIs = append(client.RedirectURIs, "https://example.com/[callback")

	err := clientRegistration.RegisterClient(client)
	assert.Error(t, err, "Expected error for malformed redirect URI")
	assert.Contains(t, err.Error(), "malformed URL", "Expected specific error message about malformed URL")

	_, err = mockDB.Read(client.ID)
	assert.Error(t, err, "Expected error when reading client from the database")
}

func TestRegisterClient_DatabaseFailure(t *testing.T) {
	mockDB := mocks.NewInMemoryMockDB()
	mockDB.CreateFunc = func(key string, value interface{}) error {
		return fmt.Errorf("database error")
	}

	clientRegistration := NewRegistrationService(mockDB)

	client := createClient()
	err := clientRegistration.RegisterClient(client)

	assert.Error(t, err, "Expected error due to database failure")
	assert.Contains(t, err.Error(), "client registration failed", "Expected specific database error message")
}

func createClient() *models.Client {
	return models.NewClient(
		"My Client App",
		[]models.GrantTypeEnum{models.AuthorizationCode},
		[]string{"https://myclientapp.com/callback"},
		models.Confidential,
	)
}
