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

package client

import (
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/mocks"
	"github.com/vigiloauth/vigilo/internal/models"
	"github.com/vigiloauth/vigilo/pkg/client/types"
	"testing"
)

func setupTest(t *testing.T) (*mocks.MockDatabase, *models.Client) {
	mockDB := mocks.NewMockDatabase()
	client := createClient()
	t.Cleanup(func() { mockDB.Reset() })
	return mockDB, client
}

func TestRegisterClient_ValidData(t *testing.T) {
	mockDB, client := setupTest(t)
	response, err := RegisterClient(client.Name, client.GrantTypes, client.RedirectURIs, client.ClientType, mockDB)
	registeredClient, err := mockDB.Read(response.ClientID)

	assert.NotNil(t, registeredClient, "Registered client should not be nil in the database")
	assert.NoError(t, err, "Expected no error")
	assert.NotNil(t, response, "Expected a valid registration response")
	assert.NotEqual(t, "client-id-123", registeredClient.(models.Client).ID, "Expected ClientID to be encrypted")
	assert.NotEqual(t, "secret123", registeredClient.(models.Client).Secret, "Expected ClientSecret to be encrypted")
	assert.Equal(t, client.RedirectURIs, registeredClient.(models.Client).RedirectURIs, "Expected correct RedirectURIs")
}

func TestRegisterClient_InvalidData(t *testing.T) {
	mockDB, client := setupTest(t)
	client.RedirectURIs = nil

	response, err := RegisterClient(client.Name, client.GrantTypes, client.RedirectURIs, client.ClientType, mockDB)

	assert.Error(t, err, "Expected error")
	assert.Nil(t, response, "Expected nil response")
}

func TestRegisterClient_StoresRedirectURIs(t *testing.T) {
	mockDB, client := setupTest(t)
	response, err := RegisterClient(client.Name, client.GrantTypes, client.RedirectURIs, client.ClientType, mockDB)
	registeredClient, err := mockDB.Read(response.ClientID)

	assert.NoError(t, err, "Expected no error reading client from the database")
	assert.NotNil(t, registeredClient, "Registered client should not be nil in the database")
	assert.NotNil(t, response, "Expected a valid registration response")
	assert.Equal(t, client.RedirectURIs, registeredClient.(models.Client).RedirectURIs, "RedirectURIs should match the ones provided during registration")
}

func createClient() *models.Client {
	return &models.Client{
		Name:         "Test Client",
		GrantTypes:   []types.GrantTypeEnum{types.AuthorizationCode},
		RedirectURIs: []string{"https://example.com/callback"},
		ClientType:   types.Confidential,
	}
}
