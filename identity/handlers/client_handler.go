package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/vigiloauth/vigilo/internal/client"
	service "github.com/vigiloauth/vigilo/internal/client/service"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
)

type ClientHandler struct {
	clientService service.ClientService
}

func NewClientHandler(clientService service.ClientService) *ClientHandler {
	return &ClientHandler{clientService: clientService}
}

func (h *ClientHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req client.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w, err)
		return
	}

	if req.Type != client.Public {
		err := errors.NewClientError(errors.ErrCodeBadRequest, "Client type must be public", "")
		utils.WriteError(w, err)
		return
	}

	if err := req.Validate(); err != nil {
		utils.WriteError(w, err)
		return
	}

	newClient := &client.Client{
		Name:         req.Name,
		Type:         req.Type,
		RedirectURIS: req.RedirectURIS,
		GrantTypes:   req.GrantTypes,
	}

	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		newClient.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}

	response, err := h.clientService.CreatePublicClient(newClient)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	utils.WriteJSON(w, http.StatusCreated, response)
}
