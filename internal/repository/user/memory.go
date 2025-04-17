package repository

import (
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var (
	logger                       = config.GetServerConfig().Logger()
	_        user.UserRepository = (*InMemoryUserRepository)(nil)
	instance *InMemoryUserRepository
	once     sync.Once
)

const module = "InMemoryUserRepository"

// InMemoryUserRepository implements the UserStore interface using an in-memory map.
type InMemoryUserRepository struct {
	users map[string]*user.User
	mu    sync.RWMutex
}

// GetInMemoryUserRepository returns the singleton instance of InMemoryUserRepository.
//
// Returns:
//
//	*InMemoryUserRepository: The singleton instance of InMemoryUserRepository.
func GetInMemoryUserRepository() *InMemoryUserRepository {
	once.Do(func() {
		logger.Debug(module, "Creating new instance of InMemoryUserRepository")
		instance = &InMemoryUserRepository{users: make(map[string]*user.User)}
	})
	return instance
}

// ResetInMemoryUserRepository resets the in-memory user store for testing purposes.
func ResetInMemoryUserRepository() {
	if instance != nil {
		logger.Debug(module, "Resetting instance")
		instance.mu.Lock()
		instance.users = make(map[string]*user.User)
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
func (u *InMemoryUserRepository) AddUser(user *user.User) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if _, ok := u.users[user.ID]; ok {
		logger.Debug(module, "AddUser: user already exists with the given ID=%s", user.ID)
		return errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided ID")
	}

	if _, ok := u.users[user.Email]; ok {
		logger.Debug(module, "AddUser: user already exists with the given email=%s", user.Email)
		return errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided email")
	}

	u.users[user.ID] = user

	return nil
}

func (u *InMemoryUserRepository) GetUserByUsername(username string) *user.User {
	u.mu.RLock()
	defer u.mu.RUnlock()

	for _, user := range u.users {
		if user.Username == username {
			logger.Debug(module, "GetUserByUsername: User found with the given username=%s", username)
			return user
		}
	}

	logger.Debug(module, "GetUserByUsername: User not found with the given username=%s", username)
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
func (u *InMemoryUserRepository) GetUserByID(userID string) *user.User {
	u.mu.RLock()
	defer u.mu.RUnlock()

	user, found := u.users[userID]
	if !found {
		logger.Debug(module, "GetUserByID: User not found with the given ID=%s", userID)
		return nil
	}

	return user
}

// GetUserByEmail retrieves a user from the store using their email.
func (u *InMemoryUserRepository) GetUserByEmail(email string) *user.User {
	u.mu.RLock()
	defer u.mu.RUnlock()

	for _, user := range u.users {
		if user.Email == email {
			logger.Debug(module, "GetUserByEmail: User found with the given email=%s", email)
			return user
		}
	}

	logger.Debug(module, "GetUserByEmail: User not found with the given email=%s", email)
	return nil
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
func (u *InMemoryUserRepository) DeleteUserByID(userID string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.users, userID)
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
func (u *InMemoryUserRepository) UpdateUser(user *user.User) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if _, ok := u.users[user.ID]; !ok {
		logger.Debug(module, "UpdateUser: User not found with the given ID=%s", user.ID)
		return errors.New(
			errors.ErrCodeUserNotFound,
			"user does not exist with the provided ID",
		)
	}

	u.users[user.Email] = user
	return nil
}

// FindUnverifiedUsersOlderThanWeek retrieves users that have not been verified
// and who's account has been created over a week ago.
//
// Returns:
//
//	[]*User: A slice of users.
func (u *InMemoryUserRepository) FindUnverifiedUsersOlderThanWeek() []*user.User {
	var expiredUsers []*user.User
	oneWeekAgo := time.Now().AddDate(0, 0, -7) // 7 days ago

	for _, user := range u.users {
		if !user.Verified && user.CreatedAt.Before(oneWeekAgo) {
			expiredUsers = append(expiredUsers, user)
		}
	}

	return expiredUsers
}
