package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/vigiloauth/vigilo/internal/client"
	service "github.com/vigiloauth/vigilo/internal/client/service"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// ClientHandler handles HTTP requests related to client operations.
type ClientHandler struct {
	clientService service.ClientService
}

// NewClientHandler creates a new instance of ClientHandler.
//
// Parameters:
//
//	clientService service.ClientService: The client service.
//
// Returns:
//
//	*ClientHandler: A new ClientHandler instance.
func NewClientHandler(clientService service.ClientService) *ClientHandler {
	return &ClientHandler{clientService: clientService}
}

// RegisterClient is the HTTP handler for public client registration.
// It process incoming HTTP requests for registering public clients, and
// returns an appropriate response.
func (h *ClientHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	var req client.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w, err)
		return
	}

	if req.Type != client.Public {
		err := errors.New(
			errors.ErrCodeInvalidClient,
			"the client is public but is being registered as confidential",
		)
		utils.WriteError(w, err)
		return
	}

	if err := req.Validate(); err != nil {
		utils.WriteError(w, err)
		return
	}

	newClient := &client.Client{
		Name:          req.Name,
		Type:          req.Type,
		RedirectURIS:  req.RedirectURIS,
		GrantTypes:    req.GrantTypes,
		ResponseTypes: req.ResponseTypes,
	}

	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		newClient.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}

	response, err := h.clientService.SaveClient(newClient)
	if err != nil {
		utils.WriteError(w, err)
		return
	}

	utils.WriteJSON(w, http.StatusCreated, response)
}
