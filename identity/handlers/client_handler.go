package handlers

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// ClientHandler handles HTTP requests related to client operations.
type ClientHandler struct {
	clientService client.ClientService
	logger        *config.Logger
	module        string
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
	return &ClientHandler{
		clientService: clientService,
		logger:        config.GetServerConfig().Logger(),
		module:        "Client Handler",
	}
}

// RegisterClient is the HTTP handler for public client registration.
func (h *ClientHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[RegisterClient]", requestID)

	req, err := web.DecodeJSONRequest[client.ClientRegistrationRequest](w, r)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Failed to decode request body: %v", requestID, err)
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	if err := req.Validate(); err != nil {
		web.WriteError(w, err)
		return
	}

	newClient := &client.Client{
		Name:          req.Name,
		Type:          req.Type,
		RedirectURIS:  req.RedirectURIS,
		GrantTypes:    req.GrantTypes,
		ResponseTypes: req.ResponseTypes,
		Scopes:        req.Scopes,
	}

	if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
		newClient.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}

	response, err := h.clientService.Register(newClient)
	if err != nil {
		h.logger.Error(h.module, "RequestID=[%s]: Failed to register client: %v", requestID, err)
		wrappedErr := errors.Wrap(err, "", "failed to register client")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[RegisterClient]", requestID)
	web.WriteJSON(w, http.StatusCreated, response)
}

// RegenerateSecret is the HTTP handler for regenerating client secrets.
func (h *ClientHandler) RegenerateSecret(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[RegenerateSecret]", requestID)

	clientID := chi.URLParam(r, common.ClientID)
	response, err := h.clientService.RegenerateClientSecret(clientID)
	if err != nil {
		web.WriteError(w, errors.Wrap(err, "", "failed to regenerate client_secret"))
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[RegenerateSecret]", requestID)
	web.WriteJSON(w, http.StatusOK, response)
}

// ManageClientConfiguration handles client configuration management requests.
// It supports GET, PUT, and DELETE methods to retrieve, update, or delete client configurations.
// The method validates the registration access token and extracts the client ID from the URL.
func (h *ClientHandler) ManageClientConfiguration(w http.ResponseWriter, r *http.Request) {
	requestID := common.GetRequestID(r.Context())
	registrationAccessToken, err := web.ExtractBearerToken(r)
	if err != nil {
		wrappedErr := errors.Wrap(
			err, errors.ErrCodeInvalidToken,
			"registration access token is not present in the authorization header",
		)
		web.WriteError(w, wrappedErr)
		return
	}

	clientID := chi.URLParam(r, common.ClientID)
	switch r.Method {
	case http.MethodGet:
		h.getClient(w, clientID, registrationAccessToken, requestID)
	case http.MethodPut:
		h.updateClient(w, r, clientID, registrationAccessToken, requestID)
	case http.MethodDelete:
		h.deleteClient(w, clientID, registrationAccessToken, requestID)
	default:
		err := errors.New(errors.ErrCodeMethodNotAllowed, fmt.Sprintf("method '%s' not allowed for this request", r.Method))
		web.WriteError(w, err)
		return
	}
}

// getClient retrieves client information for the given client ID and registration access token.
// It validates the token and client, then writes the client information as a JSON response.
func (h *ClientHandler) getClient(w http.ResponseWriter, clientID, registrationAccessToken, requestID string) {
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[GetClient]", requestID)

	clientInformation, err := h.clientService.ValidateAndRetrieveClient(clientID, registrationAccessToken)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to validate and retrieve client information")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[GetClient]", requestID)
	web.WriteJSON(w, http.StatusOK, clientInformation)
}

// updateClient updates the client configuration for the given client ID and registration access token.
// It uses the ValidateAndUpdateClient service method to perform the update.
func (h *ClientHandler) updateClient(w http.ResponseWriter, r *http.Request, clientID, registrationAccessToken, requestID string) {
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[UpdateClient]", requestID)

	request, err := web.DecodeJSONRequest[client.ClientUpdateRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	clientInformation, err := h.clientService.ValidateAndUpdateClient(clientID, registrationAccessToken, request)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to validate and update client")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[UpdateClient]", requestID)
	web.WriteJSON(w, http.StatusOK, clientInformation)
}

// deleteClient deletes the client configuration for the given client ID and registration access token.
// It uses the ValidateAndDeleteClient service method to perform the deletion.
func (h *ClientHandler) deleteClient(w http.ResponseWriter, clientID, registrationAccessToken, requestID string) {
	h.logger.Info(h.module, "RequestID=[%s]: Processing request=[DeleteClient]", requestID)

	if err := h.clientService.ValidateAndDeleteClient(clientID, registrationAccessToken); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to validate and delete client")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, "RequestID=[%s]: Successfully processed request=[DeleteClient]", requestID)
	web.SetNoStoreHeader(w)
	w.WriteHeader(http.StatusNoContent)
}
