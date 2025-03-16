package client

import (
	"sync"

	"github.com/vigiloauth/vigilo/internal/client"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ ClientStore = (*InMemoryClientStore)(nil)

type InMemoryClientStore struct {
	data map[string]*client.Client
	mu   sync.RWMutex
}

var instance *InMemoryClientStore
var once sync.Once

func GetInMemoryClientStore() *InMemoryClientStore {
	once.Do(func() {
		instance = NewInMemoryClientStore()
	})
	return instance
}

func NewInMemoryClientStore() *InMemoryClientStore {
	return &InMemoryClientStore{data: make(map[string]*client.Client)}
}

func (cs *InMemoryClientStore) CreateClient(client *client.Client) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, clientExists := cs.data[client.ID]; clientExists {
		return errors.NewDuplicateClientError()
	}

	cs.data[client.ID] = client
	return nil
}

func (cs *InMemoryClientStore) GetClient(clientID string) *client.Client {
	cs.mu.RLock()
	defer cs.mu.RUnlock()

	client, found := cs.data[clientID]
	if !found {
		return nil
	}

	return client
}

func (cs *InMemoryClientStore) DeleteClient(clientID string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.data, clientID)
	return nil
}

func (cs *InMemoryClientStore) UpdateClient(client *client.Client) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	if _, clientExists := cs.data[client.ID]; !clientExists {
		return errors.NewClientNotFoundError()
	}

	cs.data[client.ID] = client
	return nil
}
