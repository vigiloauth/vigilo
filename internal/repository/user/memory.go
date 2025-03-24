package repository

import (
	"sync"

	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var (
	_        user.UserRepository = (*InMemoryUserRepository)(nil)
	instance *InMemoryUserRepository
	once     sync.Once
)

// InMemoryUserRepository implements the UserStore interface using an in-memory map.
type InMemoryUserRepository struct {
	data map[string]*user.User
	mu   sync.RWMutex
}

// GetInMemoryUserRepository returns the singleton instance of InMemoryUserRepository.
//
// Returns:
//
//	*InMemoryUserRepository: The singleton instance of InMemoryUserRepository.
func GetInMemoryUserRepository() *InMemoryUserRepository {
	once.Do(func() {
		instance = &InMemoryUserRepository{data: make(map[string]*user.User)}
	})
	return instance
}

// ResetInMemoryUserRepository resets the in-memory user store for testing purposes.
func ResetInMemoryUserRepository() {
	if instance != nil {
		instance.mu.Lock()
		instance.data = make(map[string]*user.User)
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
//	error: An error if the user cannot be added, or nil if successful.
func (c *InMemoryUserRepository) AddUser(user *user.User) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.data[user.ID]; ok {
		return errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided email")
	}

	c.data[user.ID] = user
	return nil
}

// GetUserByID retrieves a user from the store using their ID.
//
// Parameters:
//
//	userID string: The ID used to retrieve the user.
//
// Returns:
//
//	*User: The User object if found, or nil if not found.
func (c *InMemoryUserRepository) GetUserByID(userID string) *user.User {
	c.mu.RLock()
	defer c.mu.RUnlock()

	user, found := c.data[userID]
	if !found {
		return nil
	}

	return user
}

// DeleteUserByID removes a user from the repository using their ID.
//
// Parameters:
//
//	userID string: The id used to identify the user to delete.
//
// Returns:
//
//	error: An error if the user cannot be deleted, or nil if successful.
func (c *InMemoryUserRepository) DeleteUserByID(userID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, userID)
	return nil
}

// UpdateUser updates an existing user's information in the store.
//
// Parameters:
//
//	user *user.User: The User object with updated information.
//
// Returns:
//
//	error: An error if the user cannot be updated, or nil if successful.
func (c *InMemoryUserRepository) UpdateUser(user *user.User) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.data[user.ID]; !ok {
		return errors.New(
			errors.ErrCodeUserNotFound,
			"user does not exist with the provided ID",
		)
	}

	c.data[user.Email] = user
	return nil
}
