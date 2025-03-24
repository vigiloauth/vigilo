package repository

import (
	"sync"

	domain "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var (
	_        domain.ClientRepository = (*InMemoryClientRepository)(nil)
	instance *InMemoryClientRepository
	once     sync.Once
)

// InMemoryClientRepository provides an in-memory implementation of ClientStore.
// It uses a map to store clients and a read-write mutex for concurrency control.
type InMemoryClientRepository struct {
	data map[string]*domain.Client
	mu   sync.RWMutex
}

// NewInMemoryClientRepository initializes a new InMemoryClientStore instance.
//
// Returns:
//
//	*InMemoryClientStore: A new in-memory client store.
func NewInMemoryClientRepository() *InMemoryClientRepository {
	return &InMemoryClientRepository{data: make(map[string]*domain.Client)}
}

// GetInMemoryClientRepository returns a singleton instance of InMemoryClientStore.
// It ensures that only one instance is created using sync.Once.
//
// Returns:
//
//	*InMemoryClientStore: The singleton instance of InMemoryClientStore.
func GetInMemoryClientRepository() *InMemoryClientRepository {
	once.Do(func() {
		instance = &InMemoryClientRepository{
			data: make(map[string]*domain.Client),
		}
	})
	return instance
}

// ResetInMemoryClientRepository resets the in-memory store for testing purposes.
func ResetInMemoryClientRepository() {
	if instance != nil {
		instance.mu.Lock()
		instance.data = make(map[string]*domain.Client)
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
func (cs *InMemoryClientRepository) SaveClient(client *domain.Client) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, clientExists := cs.data[client.ID]; clientExists {
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
func (cs *InMemoryClientRepository) GetClientByID(clientID string) *domain.Client {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	client, found := cs.data[clientID]
	if !found {
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
func (cs *InMemoryClientRepository) UpdateClient(client *domain.Client) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, clientExists := cs.data[client.ID]; !clientExists {
		return errors.New(errors.ErrCodeClientNotFound, "client not found using provided ID")
	}

	cs.data[client.ID] = client
	return nil
}
