package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

// ClientHandler handles HTTP requests related to client operations.
type ClientHandler struct {
	creator client.ClientCreator
	manager client.ClientManager
	logger  *config.Logger
	module  string
}

func NewClientHandler(
	creator client.ClientCreator,
	manager client.ClientManager,
) *ClientHandler {
	return &ClientHandler{
		creator: creator,
		manager: manager,
		logger:  config.GetServerConfig().Logger(),
		module:  "Client Handler",
	}
}

// RegisterClient is the HTTP handler for public client registration.
func (h *ClientHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), constants.ThreeSecondTimeout)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[RegisterClient]: Processing request")

	req, err := web.DecodeJSONRequest[client.ClientRegistrationRequest](w, r)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to decode request body: %v", err)
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	response, err := h.creator.Register(ctx, req)
	if err != nil {
		h.logger.Error(h.module, requestID, "Failed to register client: %v", err)
		wrappedErr := errors.Wrap(err, "", "failed to register client")
		web.WriteError(w, wrappedErr)
		return
	}

	h.logger.Info(h.module, requestID, "[RegisterClient]: Successfully processed request")
	web.WriteJSON(w, http.StatusCreated, response)
}

// RegenerateSecret is the HTTP handler for regenerating client secrets.
func (h *ClientHandler) RegenerateSecret(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), constants.ThreeSecondTimeout)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[RegenerateSecret]: Processing request")

	clientID := chi.URLParam(r, constants.ClientIDReqField)
	response, err := h.manager.RegenerateClientSecret(ctx, clientID)
	if err != nil {
		web.WriteError(w, errors.Wrap(err, "", "failed to regenerate client_secret"))
		return
	}

	h.logger.Info(h.module, requestID, "[RegenerateSecret]: Successfully processed request")
	web.WriteJSON(w, http.StatusOK, response)
}

func (h *ClientHandler) GetClientByID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), constants.ThreeSecondTimeout)
	defer cancel()

	requestID := utils.GetRequestID(ctx)
	h.logger.Info(h.module, requestID, "[GetClientByID]: Processing request")

	clientID := chi.URLParam(r, constants.ClientIDReqField)
	retrievedClient, err := h.manager.GetClientByID(ctx, clientID)
	if err != nil {
		web.WriteError(w, errors.Wrap(err, "", "failed to retrieve client by ID"))
		return
	}

	response := &client.ClientReadResponse{
		ID:      retrievedClient.ID,
		Name:    retrievedClient.Name,
		LogoURI: retrievedClient.LogoURI,
	}

	web.WriteJSON(w, http.StatusOK, response)
}

// ManageClientConfiguration handles client configuration management requests.
// It supports GET, PUT, and DELETE methods to retrieve, update, or delete client configurations.
// The method validates the registration access token and extracts the client ID from the URL.
func (h *ClientHandler) ManageClientConfiguration(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), constants.ThreeSecondTimeout)
	defer cancel()

	var registrationAccessToken string
	if token := utils.GetValueFromContext(ctx, constants.ContextKeyAccessToken); token != nil {
		registrationAccessToken, _ = token.(string)
	}

	clientID := chi.URLParam(r, constants.ClientIDReqField)
	switch r.Method {
	case http.MethodGet:
		h.getClient(w, clientID, registrationAccessToken, ctx)
	case http.MethodPut:
		h.updateClient(w, r, clientID, registrationAccessToken, ctx)
	case http.MethodDelete:
		h.deleteClient(w, clientID, registrationAccessToken, ctx)
	default:
		err := errors.New(errors.ErrCodeMethodNotAllowed, fmt.Sprintf("method '%s' not allowed for this request", r.Method))
		web.WriteError(w, err)
		return
	}
}

// getClient retrieves client information for the given client ID and registration access token.
// It validates the token and client, then writes the client information as a JSON response.
func (h *ClientHandler) getClient(w http.ResponseWriter, clientID, registrationAccessToken string, ctx context.Context) {
	clientInformation, err := h.manager.GetClientInformation(ctx, clientID, registrationAccessToken)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to validate and retrieve client information")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, clientInformation)
}

// updateClient updates the client configuration for the given client ID and registration access token.
// It uses the ValidateAndUpdateClient service method to perform the update.
func (h *ClientHandler) updateClient(w http.ResponseWriter, r *http.Request, clientID, registrationAccessToken string, ctx context.Context) {
	request, err := web.DecodeJSONRequest[client.ClientUpdateRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	clientInformation, err := h.manager.UpdateClientInformation(ctx, clientID, registrationAccessToken, request)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to validate and update client")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, clientInformation)
}

// deleteClient deletes the client configuration for the given client ID and registration access token.
// It uses the ValidateAndDeleteClient service method to perform the deletion.
func (h *ClientHandler) deleteClient(w http.ResponseWriter, clientID, registrationAccessToken string, ctx context.Context) {
	if err := h.manager.DeleteClientInformation(ctx, clientID, registrationAccessToken); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to validate and delete client")
		web.WriteError(w, wrappedErr)
		return
	}

	web.SetNoStoreHeader(w)
	w.WriteHeader(http.StatusNoContent)
}
