package client

import (
	"time"

	"github.com/google/uuid"
	"github.com/vigiloauth/vigilo/internal/client"
	store "github.com/vigiloauth/vigilo/internal/client/store"
	"github.com/vigiloauth/vigilo/internal/errors"
)

type ClientService interface {
	CreatePublicClient(newClient *client.Client) (*client.ClientRegistrationResponse, error)
}

var _ ClientService = (*ClientServiceImpl)(nil)

type ClientServiceImpl struct {
	clientStore store.ClientStore
}

func NewClientService(clientStore store.ClientStore) *ClientServiceImpl {
	return &ClientServiceImpl{clientStore: clientStore}
}

func (cs *ClientServiceImpl) CreatePublicClient(newClient *client.Client) (*client.ClientRegistrationResponse, error) {
	clientID, err := cs.generateUniqueClientID()
	if err != nil {
		return nil, errors.Wrap(err, "error generating client ID")
	}

	newClient.ID = clientID
	newClient.CreatedAt = time.Now()
	newClient.UpdatedAt = time.Now()

	if err := cs.clientStore.CreateClient(newClient); err != nil {
		return nil, errors.Wrap(err, "error creating client")
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

	return "", errors.NewBaseError(
		errors.ErrCodeInternalServerError,
		"failed to generate unique client ID after multiple retires",
	)
}
