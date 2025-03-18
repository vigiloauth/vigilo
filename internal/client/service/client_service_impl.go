package client

import (
	"time"

	"github.com/google/uuid"
	"github.com/vigiloauth/vigilo/internal/client"
	store "github.com/vigiloauth/vigilo/internal/client/store"
	"github.com/vigiloauth/vigilo/internal/errors"
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

// CreatePublicClient registers a new public client.
//
// Parameters:
//
//	newClient *client.Client: The client to be registered.
//
// Returns:
//
//	*client.ClientRegistrationResponse: The response containing client details.
//	error: An error if registration fails.
func (cs *ClientServiceImpl) CreatePublicClient(newClient *client.Client) (*client.ClientRegistrationResponse, error) {
	clientID, err := cs.generateUniqueClientID()
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to generate client ID")
	}

	newClient.ID = clientID
	newClient.CreatedAt = time.Now()
	newClient.UpdatedAt = time.Now()

	if err := cs.clientStore.CreateClient(newClient); err != nil {
		return nil, errors.Wrap(err, "", "failed to create new public client")
	}

	return &client.ClientRegistrationResponse{
		ID:                      newClient.ID,
		Type:                    newClient.Type,
		RedirectURIS:            newClient.RedirectURIS,
		GrantTypes:              newClient.GrantTypes,
		Scopes:                  newClient.Scopes,
		CreatedAt:               newClient.CreatedAt,
		UpdatedAt:               newClient.UpdatedAt,
		TokenEndpointAuthMethod: newClient.TokenEndpointAuthMethod,
	}, nil
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
		if existingClient := cs.clientStore.GetClient(clientID); existingClient == nil {
			return clientID, nil
		}
		time.Sleep(retryDelay)
	}

	return "", errors.New(
		errors.ErrCodeInternalServerError,
		"failed to generate unique client ID after multiple retries",
	)
}
