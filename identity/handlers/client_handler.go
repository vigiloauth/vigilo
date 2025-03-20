package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

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
func (h *ClientHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	var req client.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteError(w, errors.NewInternalServerError())
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

// write integration tests
// clean up integration tests
// Send message when secret is regenerated
// Write docs

// RegenerateSecret is the HTTP handler for regenerating client secrets.
func (h *ClientHandler) RegenerateSecret(w http.ResponseWriter, r *http.Request) {
	clientID := h.extractClientIDFromURL(w, r)
	if clientID == "" {
		utils.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "missing 'client_id' in request"))
	}

	response, err := h.clientService.RegenerateClientSecret(clientID)
	if err != nil {
		utils.WriteError(w, errors.Wrap(err, "", "failed to regenerate client_secret"))
		return
	}

	utils.WriteJSON(w, http.StatusOK, response)
}

func (h *ClientHandler) extractClientIDFromURL(w http.ResponseWriter, r *http.Request) string {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		utils.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "invalid URL"))
		return ""
	}
	return parts[len(parts)-2]
}
