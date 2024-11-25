package users

import (
	"github.com/vigiloauth/vigilo/internal/errors"
	"sync"
)

type UserCache struct {
	data map[string]User
	mu   sync.RWMutex
}

var instance *UserCache
var once sync.Once

func GetUserCache() *UserCache {
	once.Do(func() {
		instance = &UserCache{
			data: make(map[string]User),
		}
	})
	return instance
}

func (c *UserCache) AddUser(user User) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.data[user.Email]; ok {
		return errors.NewDuplicateUserError("email")
	}

	c.data[user.Email] = user
	return nil
}

func (c *UserCache) GetUser(email string) (User, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	user, found := c.data[email]
	return user, found
}
