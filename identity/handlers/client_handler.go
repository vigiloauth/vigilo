package handlers

import (
	"net/http"

	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// ClientHandler handles HTTP requests related to client operations.
type ClientHandler struct {
	clientService client.ClientService
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
func NewClientHandler(clientService client.ClientService) *ClientHandler {
	return &ClientHandler{clientService: clientService}
}

// RegisterClient is the HTTP handler for public client registration.
func (h *ClientHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	req, err := web.DecodeJSONRequest[client.ClientRegistrationRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	if err := req.Validate(); err != nil {
		web.WriteError(w, errors.NewRequestValidationError(err))
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
		wrappedErr := errors.Wrap(err, "", "failed to save client")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusCreated, response)
}

// RegenerateSecret is the HTTP handler for regenerating client secrets.
func (h *ClientHandler) RegenerateSecret(w http.ResponseWriter, r *http.Request) {
	clientID, err := web.ExtractIDFromURL(w, r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "'client_id' is missing in the request")
		web.WriteError(w, wrappedErr)
		return
	}

	response, err := h.clientService.RegenerateClientSecret(clientID)
	if err != nil {
		web.WriteError(w, errors.Wrap(err, "", "failed to regenerate client_secret"))
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}
