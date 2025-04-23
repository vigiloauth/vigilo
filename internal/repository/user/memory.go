package repository

import (
	"context"
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/common"
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
//   - *InMemoryUserRepository: The singleton instance of InMemoryUserRepository.
func GetInMemoryUserRepository() *InMemoryUserRepository {
	once.Do(func() {
		logger.Debug(module, "", "Creating new instance of InMemoryUserRepository")
		instance = &InMemoryUserRepository{users: make(map[string]*user.User)}
	})
	return instance
}

// ResetInMemoryUserRepository resets the in-memory user store for testing purposes.
func ResetInMemoryUserRepository() {
	if instance != nil {
		logger.Debug(module, "", "Resetting instance")
		instance.mu.Lock()
		instance.users = make(map[string]*user.User)
		instance.mu.Unlock()
	}
}

// AddUser adds a new user to the store.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - user *User: The User object to add.
//
// Returns:
//   - error: An error if the user cannot be added, or nil if successful.
func (u *InMemoryUserRepository) AddUser(ctx context.Context, user *user.User) error {
	requestID := common.GetRequestID(ctx)
	if err := ctx.Err(); err != nil {
		logger.Debug(module, requestID, "[AddUser]: Context already cancelled")
		return err
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if _, ok := u.users[user.ID]; ok {
		logger.Error(module, requestID, "[AddUser]: user already exists with the given ID=[%s]", user.ID)
		return errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided ID")
	}

	u.users[user.ID] = user
	return nil
}

// GetUserByUsername fetches a user by their username.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - username string: The username of the user to retrieve.
//
// Returns:
//   - *User: The retrieved user, otherwise nil.
//   - error: If an error occurs retrieving the user.
func (u *InMemoryUserRepository) GetUserByUsername(ctx context.Context, username string) (*user.User, error) {
	requestID := common.GetRequestID(ctx)
	if err := ctx.Err(); err != nil {
		logger.Debug(module, requestID, "[GetUserByUsername]: Context already cancelled")
		return nil, err
	}

	u.mu.RLock()
	defer u.mu.RUnlock()

	for _, user := range u.users {
		if user.Username == username {
			logger.Debug(module, requestID, "[GetUserByUsername]: User found with the given username=[%s]", username)
			return user, nil
		}
	}

	logger.Debug(module, requestID, "[GetUserByUsername]: User not found with the given username=[%s]", username)
	return nil, nil
}

// GetUserByID retrieves a user from the store using their ID.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The ID used to retrieve the user.
//
// Returns:
//   - *User: The User object if found, or nil if not found.
//   - error: If an error occurs retrieving the user.
func (u *InMemoryUserRepository) GetUserByID(ctx context.Context, userID string) (*user.User, error) {
	requestID := common.GetRequestID(ctx)
	if err := ctx.Err(); err != nil {
		logger.Debug(module, requestID, "[GetUserByID]: Context already cancelled")
		return nil, err
	}

	u.mu.RLock()
	defer u.mu.RUnlock()

	user, found := u.users[userID]
	if !found {
		logger.Debug(module, requestID, "[GetUserByID]: User not found with the given ID=[%s]", userID)
		return nil, nil
	}

	return user, nil
}

// GetUserByEmail retrieves a user from the store using their email address.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - email string: The email address used to retrieve the user.
//
// Returns:
//   - *User: The User object if found, or nil if not found.
//   - error: If an error occurs retrieving the user.
func (u *InMemoryUserRepository) GetUserByEmail(ctx context.Context, email string) (*user.User, error) {
	requestID := common.GetRequestID(ctx)
	if err := ctx.Err(); err != nil {
		logger.Debug(module, requestID, "[GetUserByEmail]: Context already cancelled")
		return nil, err
	}

	u.mu.RLock()
	defer u.mu.RUnlock()

	for _, user := range u.users {
		if user.Email == email {
			logger.Debug(module, requestID, "[GetUserByEmail]: User found with the given email=[%s]", email)
			return user, nil
		}
	}

	logger.Debug(module, requestID, "[GetUserByEmail]: User not found with the given email=[%s]", email)
	return nil, nil
}

// DeleteUserByID removes a user from the repository using their ID.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The id used to identify the user to delete.
//
// Returns:
//   - error: An error if the user cannot be deleted, or nil if successful.
func (u *InMemoryUserRepository) DeleteUserByID(ctx context.Context, userID string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.users, userID)
	return nil
}

// UpdateUser updates an existing user's information in the repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - user *User: The User object with updated information.
//
// Returns:
//   - error: An error if the user cannot be updated, or nil if successful.
func (u *InMemoryUserRepository) UpdateUser(ctx context.Context, user *user.User) error {
	requestID := common.GetRequestID(ctx)
	if err := ctx.Err(); err != nil {
		logger.Debug(module, requestID, "[UpdateUser]: Context already cancelled")
		return err
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	if _, ok := u.users[user.ID]; !ok {
		logger.Debug(module, requestID, "[UpdateUser]: User not found with the given ID=[%s]", user.ID)
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
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//
// Returns:
//   - []*User: A slice of users.
//   - error: If an error occurs retrieving users.
func (u *InMemoryUserRepository) FindUnverifiedUsersOlderThanWeek(ctx context.Context) ([]*user.User, error) {
	var expiredUsers []*user.User
	oneWeekAgo := time.Now().AddDate(0, 0, -7) // 7 days ago

	for _, user := range u.users {
		if !user.Verified && user.CreatedAt.Before(oneWeekAgo) {
			expiredUsers = append(expiredUsers, user)
		}
	}

	return expiredUsers, nil
}
