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

package handlers

import (
	"encoding/json"
	"github.com/vigiloauth/vigilo/internal/clients"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
	"github.com/vigiloauth/vigilo/pkg/models"
	"net/http"
)

type ClientHandler struct {
	registration *clients.Registration
}

func NewClientHandler(registration *clients.Registration) *ClientHandler {
	return &ClientHandler{registration: registration}
}

// HandleClientRegistration handles the HTTP request for client registration.
//
// This method expects a `ClientRegistrationRequest` in the request body, validates
// it, and then attempts to register the client. If successful, it returns a `ClientRegistrationResponse`
// with the registered client's information. If any errors occur during the request processing or
// registration, appropriate error responses are returned.
//
// Args:
//   - w (http.ResponseWriter): The response writer used to send the HTTP response.
//   - r (*http.Request): The incoming HTTP request containing the registration data.
//
// Returns:
//   - None. Writes directly to the response writer.
func (h *ClientHandler) HandleClientRegistration(w http.ResponseWriter, r *http.Request) {
	var request models.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		utils.WriteError(w, &errors.BadRequestError{Message: "invalid request body"})
		return
	}

	if err := request.Validate(); err != nil {
		utils.WriteError(w, &errors.BadRequestError{Message: err.Error()})
		return
	}

	client := h.createClientFromRequest(request)
	createdClient, err := h.registration.Register(*client)
	if err != nil {
		utils.WriteError(w, &errors.ServerError{Message: err.Error()})
		return
	}

	response := h.createClientRegistrationResponse(createdClient)
	utils.WriteJSON(w, http.StatusCreated, response)
}

func (h *ClientHandler) createClientFromRequest(request models.ClientRegistrationRequest) *clients.Client {
	return &clients.Client{
		Name:         request.Name,
		RedirectURIs: request.RedirectURIs,
		Type:         request.ClientType,
		GrantTypes:   request.GrantTypes,
		Scopes:       request.Scopes,
	}
}

func (h *ClientHandler) createClientRegistrationResponse(client *clients.Client) *models.ClientRegistrationResponse {
	return &models.ClientRegistrationResponse{
		ClientID:     client.ID,
		ClientType:   client.Type,
		RedirectURIs: client.RedirectURIs,
		GrantTypes:   client.GrantTypes,
		Scope:        client.Scopes,
		CreatedAt:    client.CreatedAt,
	}
}
