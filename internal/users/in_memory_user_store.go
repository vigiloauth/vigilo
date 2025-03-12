package users

import (
	"sync"

	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
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

// ResetInMemoryUserStore resets the in-memory user store for testing purposes.
func ResetInMemoryUserStore() {
	if instance != nil {
		instance.mu.Lock()
		instance.data = make(map[string]User)
		instance.mu.Unlock()
	}
}

func (c *InMemoryUserStore) AddUser(user *User) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.data[user.Email]; ok {
		return errors.NewDuplicateUserError(utils.UserFieldConstants.Email)
	}

	c.data[user.Email] = *user
	return nil
}

func (c *InMemoryUserStore) GetUser(email string) *User {
	c.mu.RLock()
	defer c.mu.RUnlock()

	user, found := c.data[email]
	if !found {
		return nil
	}

	return &user
}

func (c *InMemoryUserStore) DeleteUser(email string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, email)
	return nil
}

func (c *InMemoryUserStore) UpdateUser(user *User) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.data[user.Email]; !ok {
		return errors.NewUserNotFoundError()
	}

	c.data[user.Email] = *user
	return nil
}
