package repository

import (
	"sync"

	"github.com/vigiloauth/vigilo/identity/config"
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
		logger.Debug(module, "Creating new instance of InMemoryClientRepository")
		instance = &InMemoryClientRepository{
			data: make(map[string]*client.Client),
		}
	})
	return instance
}

// ResetInMemoryClientRepository resets the in-memory store for testing purposes.
func ResetInMemoryClientRepository() {
	if instance != nil {
		logger.Debug(module, "Resetting instance")
		instance.mu.Lock()
		instance.data = make(map[string]*client.Client)
		instance.mu.Unlock()
	}
}

// SaveClient adds a new client to the store if it does not already exist.
//
// Parameters:
//
//	client *client.Client: The client object to store.
//
// Returns:
//
//	error: An error if the client already exists, nil otherwise.
func (cs *InMemoryClientRepository) SaveClient(client *client.Client) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, clientExists := cs.data[client.ID]; clientExists {
		logger.Debug(module, "SaveClient: Failed to save client. Duplicate ID")
		return errors.New(errors.ErrCodeDuplicateClient, "client already exists with given ID")
	}

	cs.data[client.ID] = client
	return nil
}

// GetClientByID retrieves a client by its ID.
//
// Parameters:
//
//	clientID string: The ID of the client to retrieve.
//
// Returns:
//
//	*client.Client: The client object if found, nil otherwise.
func (cs *InMemoryClientRepository) GetClientByID(clientID string) *client.Client {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	client, found := cs.data[clientID]
	if !found {
		logger.Debug(module, "GetClientByID: No client found using the given ID=%s", clientID)
		return nil
	}

	return client
}

// DeleteClientByID removes a client from the store by its ID.
//
// Parameters:
//
//	clientID string: The ID of the client to delete.
//
// Returns:
//
//	error: Always returns nil.
func (cs *InMemoryClientRepository) DeleteClientByID(clientID string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.data, clientID)
	return nil
}

// UpdateClient updates an existing client in the store.
//
// Parameters:
//
//	client *client.Client: The updated client object.
//
// Returns:
//
//	error: An error if the client does not exist, nil otherwise.
func (cs *InMemoryClientRepository) UpdateClient(client *client.Client) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, clientExists := cs.data[client.ID]; !clientExists {
		logger.Debug(module, "UpdateClient: No client found using the given ID=%s", client.ID)
		return errors.New(errors.ErrCodeClientNotFound, "client not found using provided ID")
	}

	cs.data[client.ID] = client
	return nil
}

// IsExistingID checks to see if an ID already exists in the database.
//
// Parameters:
//
//	clientID string: The client ID to verify.
//
// Returns:
//
//	bool: True if it exists, otherwise false.
func (cs *InMemoryClientRepository) IsExistingID(clientID string) bool {
	_, clientExists := cs.data[clientID]
	return clientExists
}
