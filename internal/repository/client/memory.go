package repository

import (
	"context"
	"sync"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var (
	logger                           = config.GetServerConfig().Logger()
	_        client.ClientRepository = (*InMemoryClientRepository)(nil)
	instance *InMemoryClientRepository
	once     sync.Once
)

const module = "InMemoryClientRepository"

// InMemoryClientRepository provides an in-memory implementation of ClientStore.
// It uses a map to store clients and a read-write mutex for concurrency control.
type InMemoryClientRepository struct {
	data map[string]*client.Client
	mu   sync.RWMutex
}

// NewInMemoryClientRepository initializes a new InMemoryClientStore instance.
//
// Returns:
//
//	*InMemoryClientStore: A new in-memory client store.
func NewInMemoryClientRepository() *InMemoryClientRepository {
	return &InMemoryClientRepository{data: make(map[string]*client.Client)}
}

// GetInMemoryClientRepository returns a singleton instance of InMemoryClientStore.
// It ensures that only one instance is created using sync.Once.
//
// Returns:
//
//	*InMemoryClientStore: The singleton instance of InMemoryClientStore.
func GetInMemoryClientRepository() *InMemoryClientRepository {
	once.Do(func() {
		logger.Debug(module, "", "Creating new instance of InMemoryClientRepository")
		instance = &InMemoryClientRepository{
			data: make(map[string]*client.Client),
		}
	})
	return instance
}

// ResetInMemoryClientRepository resets the in-memory store for testing purposes.
func ResetInMemoryClientRepository() {
	if instance != nil {
		logger.Debug(module, "", "Resetting instance")
		instance.mu.Lock()
		instance.data = make(map[string]*client.Client)
		instance.mu.Unlock()
	}
}

// SaveClient adds a new client to the store if it does not already exist.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - client *Client: The client object to store.
//
// Returns:
//   - error: An error if the client already exists, nil otherwise.
func (cs *InMemoryClientRepository) SaveClient(ctx context.Context, client *client.Client) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, clientExists := cs.data[client.ID]; clientExists {
		logger.Error(module, "", "[SaveClient]: Failed to save client. Duplicate ID")
		return errors.New(errors.ErrCodeDuplicateClient, "client already exists with given ID")
	}

	cs.data[client.ID] = client
	return nil
}

// GetClientByID retrieves a client by its ID.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client to retrieve.
//
// Returns:
//   - *Client: The client object if found, nil otherwise.
func (cs *InMemoryClientRepository) GetClientByID(ctx context.Context, clientID string) (*client.Client, error) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	requestID := common.GetRequestID(ctx)
	client, found := cs.data[clientID]
	if !found {
		logger.Debug(module, requestID, "[GetClientByID]: No client found using the given ID=%s", clientID)
		return nil, nil
	}

	return client, nil
}

// DeleteClientByID removes a client from the store by its ID.
// DeleteClient removes a client from the store by its ID.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client to delete.
//
// Returns:
//   - error: Returns an error if deletion fails, otherwise false.
func (cs *InMemoryClientRepository) DeleteClientByID(ctx context.Context, clientID string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.data, clientID)
	return nil
}

// UpdateClient updates an existing client in the store.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - client *Client: The updated client object.
//
// Returns:
//   - error: An error if the client does not exist, nil otherwise.
func (cs *InMemoryClientRepository) UpdateClient(ctx context.Context, client *client.Client) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	requestID := common.GetRequestID(ctx)
	if _, clientExists := cs.data[client.ID]; !clientExists {
		logger.Debug(module, requestID, "[UpdateClient]: No client found using the given ID=%s", client.ID)
		return errors.New(errors.ErrCodeClientNotFound, "client not found using provided ID")
	}

	cs.data[client.ID] = client
	return nil
}

// IsExistingID checks to see if an ID already exists in the database.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The client ID to verify.
//
// Returns:
//   - bool: True if it exists, otherwise false.
func (cs *InMemoryClientRepository) IsExistingID(ctx context.Context, clientID string) bool {
	_, clientExists := cs.data[clientID]
	return clientExists
}
