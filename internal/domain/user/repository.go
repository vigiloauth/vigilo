package domain

import "context"

// UserRepository defines the interface for storing and managing user data.
type UserRepository interface {
	// AddUser adds a new user to the store.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- user *User: The User object to add.
	//
	// Returns:
	//	- error: An error if the user cannot be added, or nil if successful.
	AddUser(ctx context.Context, user *User) error

	// GetUserByID retrieves a user from the store using their ID.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - userID string: The ID used to retrieve the user.
	//
	// Returns:
	//  - *User: The User object if found, or nil if not found.
	//	- error: If an error occurs retrieving the user.
	GetUserByID(ctx context.Context, userID string) (*User, error)

	// GetUserByEmail retrieves a user from the store using their email address.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- email string: The email address used to retrieve the user.
	//
	// Returns:
	//	- *User: The User object if found, or nil if not found.
	//	- error: If an error occurs retrieving the user.
	GetUserByEmail(ctx context.Context, email string) (*User, error)

	// DeleteUserByID removes a user from the repository using their ID.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//  - userID string: The id used to identify the user to delete.
	//
	// Returns:
	//  - error: An error if the user cannot be deleted, or nil if successful.
	DeleteUserByID(ctx context.Context, userID string) error

	// UpdateUser updates an existing user's information in the repository.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	// 	- user *User: The User object with updated information.
	//
	// Returns:
	//  - error: An error if the user cannot be updated, or nil if successful.
	UpdateUser(ctx context.Context, user *User) error

	// GetUserByUsername fetches a user by their username.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- username string: The username of the user to retrieve.
	//
	// Returns:
	//	- *User: The retrieved user, otherwise nil.
	//	- error: If an error occurs retrieving the user.
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// FindUnverifiedUsersOlderThanWeek retrieves users that have not been verified
	// and who's account has been created over a week ago.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//
	// Returns:
	//	- []*User: A slice of users.
	//	- error: If an error occurs retrieving users.
	FindUnverifiedUsersOlderThanWeek(ctx context.Context) ([]*User, error)
}
