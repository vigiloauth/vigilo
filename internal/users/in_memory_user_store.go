package users

import (
	"sync"

	"github.com/vigiloauth/vigilo/internal/errors"
)

// InMemoryUserStore implements the UserStore interface using an in-memory map.
type InMemoryUserStore struct {
	data map[string]User // Map to store users, key is the user's email.
	mu   sync.RWMutex    // Read-write mutex for concurrent access.
}

var _ UserStore = (*InMemoryUserStore)(nil) // Ensures InMemoryUserStore implements UserStore.
var instance *InMemoryUserStore             // Singleton instance of InMemoryUserStore.
var once sync.Once                          // Ensures singleton initialization only once.

// GetInMemoryUserStore returns the singleton instance of InMemoryUserStore.
//
// Returns:
//
//	*InMemoryUserStore: The singleton instance of InMemoryUserStore.
func GetInMemoryUserStore() *InMemoryUserStore {
	once.Do(func() {
		instance = &InMemoryUserStore{data: make(map[string]User)}
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

// AddUser adds a new user to the store.
//
// Parameters:
//
//	user *User: The User object to add.
//
// Returns:
//
//	error: An error if the user already exists, or nil if successful.
func (c *InMemoryUserStore) AddUser(user *User) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.data[user.Email]; ok {
		return errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided email")
	}

	c.data[user.Email] = *user
	return nil
}

// GetUser retrieves a user from the store based on the email.
//
// Parameters:
//
//	email string: The email of the user to retrieve.
//
// Returns:
//
//	*User: The User object if found, or nil if not found.
func (c *InMemoryUserStore) GetUser(email string) *User {
	c.mu.RLock()
	defer c.mu.RUnlock()

	user, found := c.data[email]
	if !found {
		return nil
	}

	return &user
}

// DeleteUser removes a user from the store based on the email.
//
// Parameters:
//
//	email string: The email of the user to delete.
//
// Returns:
//
//	error: Always returns nil.
func (c *InMemoryUserStore) DeleteUser(email string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, email)
	return nil
}

// UpdateUser updates an existing user's information in the store.
//
// Parameters:
//
//	user *User: The User object with updated information.
//
// Returns:
//
//	error: An error if the user is not found, or nil if successful.
func (c *InMemoryUserStore) UpdateUser(user *User) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.data[user.Email]; !ok {
		return errors.New(errors.ErrCodeUserNotFound, "user does not exist with the provided email")
	}

	c.data[user.Email] = *user
	return nil
}
