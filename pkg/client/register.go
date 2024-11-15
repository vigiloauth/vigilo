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
	"fmt"
	"github.com/vigiloauth/vigilo/internal/config"
	"github.com/vigiloauth/vigilo/internal/models"
	"github.com/vigiloauth/vigilo/internal/services"
)

// RegisterClient registers a new client with the giving configurations and returns a registration response if successful.
// Parameters:
//   - name (string): the name of the client application being registered.
//   - grantTypes ([]types.GrantTypeEnum): A slice of types.GrantTypeEnum values representing the allowed grant types for the client.
//   - redirectURIs ([]string): A slice of valid redirect URIs for the client.
//   - clientType (types.ClientTypeEnum): The type of the client to be registered (either "public" or "confidential").
//
// Returns:
//   - When successful, it returns a pointer to a models.RegistrationResponse object containing the hashed ClientID, ClientSecret,
//     and RedirectURIs.
//   - On failure, it returns an error that describes what wrong.
//
// Error Handling:
//   - If the RegisterClient method of the services.RegistrationService encounters any error, the method will return
//     a detailed error message wrapped with the context of client registration failure.
func RegisterClient(name string, grantTypes []models.GrantTypeEnum, redirectURIs []string, clientType models.TypeEnum) (*models.RegistrationResponse, error) {
	db := config.GetDatabase()
	newClient := models.NewClient(name, grantTypes, redirectURIs, clientType)
	registration := services.NewRegistrationService(db)

	if err := registration.RegisterClient(newClient); err != nil {
		return nil, fmt.Errorf("error registering a new client: %v", err)
	}

	return &models.RegistrationResponse{
		ClientID:     newClient.ID,
		ClientSecret: *newClient.Secret,
		RedirectURIs: newClient.RedirectURIs,
	}, nil
}
