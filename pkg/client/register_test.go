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
	"github.com/vigiloauth/vigilo/internal/models"
	"testing"
)

func TestRegisterClient_ValidData(t *testing.T) {
	client := createClient()

	response, err := RegisterClient(client.Name, client.GrantTypes, client.RedirectURIs, client.ClientType)

	assert.NoError(t, err, "There should be no error when registering a client")
	assert.NotNil(t, response, "Response should not be nil")
}

func TestRegisterClient_InvalidData(t *testing.T) {
	client := createClient()
	client.RedirectURIs = nil
	response, err := RegisterClient(client.Name, client.GrantTypes, client.RedirectURIs, client.ClientType)

	assert.Error(t, err, "Expected error")
	assert.Nil(t, response, "Expected response to be nil")
}

func createClient() *models.Client {
	return &models.Client{
		Name:         "Test Client",
		GrantTypes:   []models.GrantTypeEnum{models.AuthorizationCode},
		RedirectURIs: []string{"https://example.com/callback"},
		ClientType:   models.Confidential,
	}
}
