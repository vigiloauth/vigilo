package client

import (
	"sync"

	"github.com/vigiloauth/vigilo/internal/client"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ ClientStore = (*InMemoryClientStore)(nil) // Ensure InMemoryClientStore implements the ClientStore interface.
var instance *InMemoryClientStore               // Singleton instance of InMemoryClientStore
var once sync.Once                              // Makes sure the store is only initialized once.

// InMemoryClientStore provides an in-memory implementation of ClientStore.
// It uses a map to store clients and a read-write mutex for concurrency control.
type InMemoryClientStore struct {
	data map[string]*client.Client // Map storing client data by client ID.
	mu   sync.RWMutex              // Read-write mutex for concurrent access.
}

// NewInMemoryClientStore initializes a new InMemoryClientStore instance.
//
// Returns:
//
//	*InMemoryClientStore: A new in-memory client store.
func NewInMemoryClientStore() *InMemoryClientStore {
	return &InMemoryClientStore{data: make(map[string]*client.Client)}
}

// GetInMemoryClientStore returns a singleton instance of InMemoryClientStore.
// It ensures that only one instance is created using sync.Once.
//
// Returns:
//
//	*InMemoryClientStore: The singleton instance of InMemoryClientStore.
func GetInMemoryClientStore() *InMemoryClientStore {
	once.Do(func() {
		instance = &InMemoryClientStore{data: make(map[string]*client.Client)}
	})
	return instance
}

// ResetInMemoryClientStore resets the in-memory store for testing purposes.
func ResetInMemoryClientStore() {
	if instance != nil {
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
func (cs *InMemoryClientStore) SaveClient(client *client.Client) error {
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
func (cs *InMemoryClientStore) GetClientByID(clientID string) *client.Client {
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
func (cs *InMemoryClientStore) DeleteClientByID(clientID string) error {
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
func (cs *InMemoryClientStore) UpdateClient(client *client.Client) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, clientExists := cs.data[client.ID]; !clientExists {
		return errors.New(errors.ErrCodeClientNotFound, "client not found using provided ID")
	}

	cs.data[client.ID] = client
	return nil
}
