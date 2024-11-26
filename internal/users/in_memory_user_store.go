package users

import (
	"github.com/vigiloauth/vigilo/internal/errors"
	"sync"
)

type InMemoryUserStore struct {
	data map[string]User
	mu   sync.RWMutex
}

var instance *InMemoryUserStore
var once sync.Once

func GetInMemoryUserStore() *InMemoryUserStore {
	once.Do(func() {
		instance = &InMemoryUserStore{
			data: make(map[string]User),
		}
	})
	return instance
}

func (c *InMemoryUserStore) AddUser(user User) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.data[user.Email]; ok {
		return errors.NewDuplicateUserError("email")
	}

	c.data[user.Email] = user
	return nil
}

func (c *InMemoryUserStore) GetUser(email string) (User, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	user, found := c.data[email]
	return user, found
}

func (c *InMemoryUserStore) DeleteUser(email string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, email)
	return nil
}
