package client

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/google/uuid"
	"github.com/vigiloauth/vigilo/internal/client"
	store "github.com/vigiloauth/vigilo/internal/client/store"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// Ensures that ClientServiceImpl implements the ClientService interface.
var _ ClientService = (*ClientServiceImpl)(nil)

// ClientServiceImpl provides the implementation of ClientService.
type ClientServiceImpl struct {
	clientStore store.ClientStore // Storage for client information.
}

// NewClientService creates a new instance of ClientServiceImpl.
//
// Parameters:
//
//	clientStore store.ClientStore: The client store to be used.
//
// Returns:
//
//	*ClientServiceImpl: A new instance of ClientServiceImpl.
func NewClientService(clientStore store.ClientStore) *ClientServiceImpl {
	return &ClientServiceImpl{clientStore: clientStore}
}

// SaveClient registers a new public client.
//
// Parameters:
//
//	newClient *client.Client: The client to be registered.
//
// Returns:
//
//	*client.ClientRegistrationResponse: The response containing client details.
//	error: An error if registration fails.
func (cs *ClientServiceImpl) SaveClient(newClient *client.Client) (*client.ClientRegistrationResponse, error) {
	clientID, err := cs.generateUniqueClientID()
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to generate client ID")
	}
	newClient.ID = clientID

	var plainSecret string
	if newClient.Type == client.Confidential {
		plainSecret, err = cs.generateClientSecret()
		if err != nil {
			return nil, errors.NewInternalServerError()
		}
		hashedSecret, err := utils.HashString(plainSecret)
		if err != nil {
			return nil, errors.NewInternalServerError()
		}
		newClient.Secret = hashedSecret
	}

	newClient.CreatedAt, newClient.UpdatedAt = time.Now(), time.Now()
	if err := cs.clientStore.SaveClient(newClient); err != nil {
		return nil, errors.Wrap(err, "", "failed to create new client")
	}

	response := &client.ClientRegistrationResponse{
		ID:                      newClient.ID,
		Name:                    newClient.Name,
		Type:                    newClient.Type,
		RedirectURIS:            newClient.RedirectURIS,
		GrantTypes:              newClient.GrantTypes,
		Scopes:                  newClient.Scopes,
		ResponseTypes:           newClient.ResponseTypes,
		CreatedAt:               newClient.CreatedAt,
		UpdatedAt:               newClient.UpdatedAt,
		TokenEndpointAuthMethod: newClient.TokenEndpointAuthMethod,
	}

	if newClient.Type == client.Confidential {
		response.Secret = plainSecret
	}

	return response, nil
}

// RegenerateClientSecret regenerates a client secret.
//
// Parameters
//
//	clientID string: The ID of the client.
//
// Returns:
//
//	*client.ClientSecretRegenerationResponse: If successful.
//	error: An error if the regeneration fails.
func (cs *ClientServiceImpl) RegenerateClientSecret(clientID string) (*client.ClientSecretRegenerationResponse, error) {
	if clientID == "" {
		return nil, errors.New(errors.ErrCodeEmptyInput, "missing required parameter: 'client_id'")
	}

	retrievedClient := cs.clientStore.GetClientByID(clientID)
	if retrievedClient == nil {
		return nil, errors.New(errors.ErrCodeInvalidClient, "client does not exist with the given ID")
	}
	if !retrievedClient.HasScope(client.ClientManage) {
		return nil, errors.New(errors.ErrCodeInvalidScope, "client does not have required scope 'client:manage'")
	}
	if !retrievedClient.IsConfidential() {
		return nil, errors.New(errors.ErrCodeUnauthorizedClient, "client is not type 'confidential'")
	}

	clientSecret, err := cs.generateClientSecret()
	if err != nil {
		return nil, errors.Wrap(err, "", "error generating 'client_secret'")
	}

	retrievedClient.Secret, err = utils.HashString(clientSecret)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to encrypt 'client_secret")
	}

	updatedAt := time.Now()
	retrievedClient.UpdatedAt = updatedAt
	if err := cs.clientStore.UpdateClient(retrievedClient); err != nil {
		return nil, errors.Wrap(err, "", "failed to update client")
	}

	return &client.ClientSecretRegenerationResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		UpdatedAt:    updatedAt,
	}, nil
}

// AuthenticateClientForCredentialsGrant authenticates the client using provided credentials
// and authorizes access by validating required grant types and scopes.
//
// Parameters:
//
//	clientID string: The ID of the client.
//	clientSecret string: The client secret.
//
// Returns:
//
//	*client.Client: The authenticated client if successful.
//	error: An error if authentication or authorization fails.
func (cs *ClientServiceImpl) AuthenticateClientForCredentialsGrant(clientID, clientSecret string) (*client.Client, error) {
	if clientID == "" || clientSecret == "" {
		return nil, errors.New(errors.ErrCodeEmptyInput, "missing required parameter")
	}

	existingClient := cs.clientStore.GetClientByID(clientID)
	if existingClient == nil {
		return nil, errors.New(errors.ErrCodeInvalidClient, "client does not exist with the given ID")
	}
	if !existingClient.IsConfidential() {
		return nil, errors.New(errors.ErrCodeUnauthorizedClient, "client is not type 'confidential'")
	}
	if existingClient.Secret != clientSecret {
		return nil, errors.New(errors.ErrCodeInvalidClient, "invalid 'client_secret' provided")
	}

	if !existingClient.HasGrantType(client.ClientCredentials) {
		return nil, errors.New(errors.ErrCodeInvalidGrantType, "client does not have required grant type 'client_credentials'")
	}

	if !existingClient.HasScope(client.ClientManage) {
		return nil, errors.New(errors.ErrCodeInvalidScope, "client does not have required scope 'client:manage'")
	}

	return existingClient, nil
}

// generateUniqueClientID generates a unique client ID, ensuring it is not already in use.
//
// Returns:
//
//	string: The generated unique client ID.
//	error: An error if the ID generation fails after multiple retries.
func (cs *ClientServiceImpl) generateUniqueClientID() (string, error) {
	const maxRetries = 5
	const retryDelay = 100 * time.Millisecond

	for range maxRetries {
		clientID := uuid.New().String()
		if existingClient := cs.clientStore.GetClientByID(clientID); existingClient == nil {
			return clientID, nil
		}
		time.Sleep(retryDelay)
	}

	return "", errors.NewInternalServerError()
}

// generateClientSecret generates a unique client secret, making sure it is not already in use.
//
// Returns:
//
//	string: The generated client secret.
//	error: An error if the client secret fails after multiple retries.
func (cs *ClientServiceImpl) generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", errors.NewInternalServerError()
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
