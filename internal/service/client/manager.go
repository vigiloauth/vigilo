package service

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	clients "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	crypto "github.com/vigiloauth/vigilo/v2/internal/domain/crypto"

	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

var _ clients.ClientManager = (*clientManager)(nil)

type clientManager struct {
	repo          clients.ClientRepository
	validator     clients.ClientValidator
	authenticator clients.ClientAuthenticator
	cryptographer crypto.Cryptographer

	logger *config.Logger
	module string
}

func NewClientManager(
	repo clients.ClientRepository,
	validator clients.ClientValidator,
	authenticator clients.ClientAuthenticator,
	cryptographer crypto.Cryptographer,
) clients.ClientManager {
	return &clientManager{
		repo:          repo,
		validator:     validator,
		authenticator: authenticator,
		cryptographer: cryptographer,
		logger:        config.GetServerConfig().Logger(),
		module:        "Client Manager",
	}
}

// RegenerateClientSecret regenerates the client secret for a given client ID.
// It returns a response containing the new client secret and its expiration time.
//
// Parameters:
//   - ctx context.Context: The context for the operation.
//   - clientID string: The ID of the client for which to regenerate the secret.
//
// Returns:
//   - *ClientSecretRegenerationResponse: A pointer to ClientSecretRegenerationResponse containing the new secret and expiration time.
//   - error: An error if the operation fails, or nil if successful.
func (c *clientManager) RegenerateClientSecret(
	ctx context.Context,
	clientID string,
) (*clients.ClientSecretRegenerationResponse, error) {
	requestID := utils.GetRequestID(ctx)

	client, err := c.repo.GetClientByID(ctx, clientID)
	if err != nil {
		c.logger.Error(c.module, requestID, "[RegenerateClientSecret]: Failed to retrieve client: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeUnauthorized, "failed to retrieve client")
	}

	if !client.IsConfidential() {
		return nil, errors.New(errors.ErrCodeInvalidClient, "invalid client credentials")
	}

	req := &clients.ClientAuthenticationRequest{
		ClientID:       clientID,
		ClientSecret:   client.Secret,
		RequestedGrant: constants.ClientCredentialsGrantType,
	}

	if err := c.authenticator.AuthenticateClient(ctx, req); err != nil {
		c.logger.Error(c.module, requestID, "[RegenerateClientSecret]: Failed to authenticate request: %v", err)
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	clientSecret, err := c.cryptographer.GenerateRandomString(32)
	if err != nil {
		c.logger.Error(c.module, requestID, "[RegenerateClientSecret]: Failed to generate client secret: %v", err)
		return nil, errors.NewInternalServerError()
	}

	client.Secret, err = c.cryptographer.HashString(clientSecret)
	if err != nil {
		c.logger.Error(c.module, requestID, "[RegenerateClientSecret]: Failed to encrypt client secret: %v", err)
		return nil, errors.NewInternalServerError()
	}

	client.UpdatedAt = time.Now()
	if err := c.repo.UpdateClient(ctx, client); err != nil {
		c.logger.Error(c.module, requestID, "[RegenerateClientSecret]: Failed to update client: %v", err)
		return nil, errors.Wrap(err, "", "failed to update client")
	}

	return &clients.ClientSecretRegenerationResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		UpdatedAt:    client.UpdatedAt,
	}, nil
}

// GetClientByID retrieves a client by its ID.
//
// Parameters:
//   - ctx context.Context: The context for the operation.
//   - clientID string: The ID of the client to retrieve.
//
// Returns:
//   - *Client: A pointer to the Client object if found, or nil if not found.
//   - error: An error if the operation fails, or nil if successful.
func (c *clientManager) GetClientByID(ctx context.Context, clientID string) (*clients.Client, error) {
	requestID := utils.GetRequestID(ctx)

	client, err := c.repo.GetClientByID(ctx, clientID)
	if err != nil {
		c.logger.Error(c.module, requestID, "[GetClientByID]: Failed to retrieve client by ID: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve client")
	}

	return client, nil
}

// GetClientInformation retrieves client information by client ID and registration access token.
// It returns a response containing the client information.
//
// Parameters:
//   - ctx context.Context: The context for the operation.
//   - clientID string: The ID of the client to retrieve information for.
//   - registrationAccessToken string: The registration access token for authentication.
//
// Returns:
//   - *ClientInformationResponse: A pointer to ClientInformationResponse containing the client information.
//   - error: An error if the operation fails, or nil if successful.
func (c *clientManager) GetClientInformation(
	ctx context.Context,
	clientID string,
	registrationAccessToken string,
) (*clients.ClientInformationResponse, error) {
	requestID := utils.GetRequestID(ctx)

	if err := c.validator.ValidateClientAndRegistrationAccessToken(ctx, clientID, registrationAccessToken); err != nil {
		c.logger.Error(c.module, requestID, "[GetClientInformation]: Failed to validate request")
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	// The error can be ignored here since the client was validated in the previous method
	client, _ := c.repo.GetClientByID(ctx, clientID)

	registrationClientURI := config.GetServerConfig().BaseURL() + web.ClientEndpoints.Register
	return clients.NewClientInformationResponse(
		client.ID,
		client.Secret,
		registrationClientURI,
		registrationAccessToken,
	), nil
}

// UpdateClientInformation updates the client information for a given client ID.
//
// Parameters:
//   - ctx context.Context: The context for the operation.
//   - clientID string: The ID of the client to update.
//   - registrationAccessToken string: The registration access token for authentication.
//   - request *ClientUpdateRequest: A pointer to ClientUpdateRequest containing the updated information.
//
// Returns:
//   - *ClientInformationResponse: A pointer to ClientInformationResponse containing the updated client information.
//   - error: An error if the operation fails, or nil if successful.
func (c *clientManager) UpdateClientInformation(
	ctx context.Context,
	clientID string,
	registrationAccessToken string,
	request *clients.ClientUpdateRequest,
) (*clients.ClientInformationResponse, error) {
	requestID := utils.GetRequestID(ctx)

	if err := c.validator.ValidateUpdateRequest(ctx, request); err != nil {
		c.logger.Error(c.module, requestID, "[UpdateClientInformation]: Failed to validate request: %v", err)
		return nil, errors.Wrap(err, "", "failed to validate request")
	}

	if err := c.validator.ValidateClientAndRegistrationAccessToken(ctx, clientID, registrationAccessToken); err != nil {
		c.logger.Error(c.module, requestID, "[UpdateClientInformation]: Failed to validate request")
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	// The error can be ignored here since the client was validated in the previous method
	client, _ := c.repo.GetClientByID(ctx, clientID)
	if client.IsConfidential() {
		request.Type = types.ConfidentialClient
		if !client.SecretsMatch(request.Secret) {
			c.logger.Error(c.module, requestID, "[UpdateClientInformation]: Client secret's don't match")
			return nil, errors.New(errors.ErrCodeUnauthorized, "the provided client secret is invalid or does not match the registered credentials")
		}
	}

	client.UpdateValues(request)
	if err := c.repo.UpdateClient(ctx, client); err != nil {
		c.logger.Error(c.module, requestID, "[UpdateClientInformation]: Failed to update client: %v", err)
		return nil, errors.Wrap(err, "", "failed to update client")
	}

	registrationClientURI := config.GetServerConfig().BaseURL() + web.ClientEndpoints.Register
	return clients.NewClientInformationResponse(
		client.ID,
		client.Secret,
		registrationClientURI,
		registrationAccessToken,
	), nil

}

// DeleteClientInformation deletes the client information for a given client ID.
//
// Parameters:
//   - ctx context.Context: The context for the operation.
//   - clientID string: The ID of the client to delete.
//   - registrationAccessToken string: The registration access token for authentication.
//
// Returns:
//   - error: An error if the operation fails, or nil if successful.
func (c *clientManager) DeleteClientInformation(ctx context.Context, clientID string, registrationAccessToken string) error {
	requestID := utils.GetRequestID(ctx)

	if err := c.validator.ValidateClientAndRegistrationAccessToken(ctx, clientID, registrationAccessToken); err != nil {
		c.logger.Error(c.module, requestID, "[DeleteClientInformation]: Failed to validate request")
		return errors.Wrap(err, "", "failed to validate client")
	}

	if err := c.repo.DeleteClientByID(ctx, clientID); err != nil {
		c.logger.Error(c.module, requestID, "[DeleteClientInformation]: Failed to delete client: %v", err)
		return errors.Wrap(err, "", "failed to delete client")
	}

	return nil
}
