package domain

// UserRepository defines the interface for storing and managing user data.
type UserRepository interface {
	// AddUser adds a new user to the store.
	//
	// Parameters:
	//
	//   user *User: The User object to add.
	//
	// Returns:
	//
	//   error: An error if the user cannot be added, or nil if successful.
	AddUser(user *User) error

	// GetUserByID retrieves a user from the store using their ID.
	//
	// Parameters:
	//
	//   userID string: The ID used to retrieve the user.
	//
	// Returns:
	//
	//   *User: The User object if found, or nil if not found.
	GetUserByID(userID string) *User

	// GetUserByEmail retrieves a user from the store using their email address.
	//
	// Parameters:
	//
	//   email string: The email address used to retrieve the user.
	//
	// Returns:
	//
	//   *User: The User object if found, or nil if not found.
	GetUserByEmail(email string) *User

	// DeleteUserByID removes a user from the repository using their ID.
	//
	// Parameters:
	//
	//   userID string: The id used to identify the user to delete.
	//
	// Returns:
	//
	//   error: An error if the user cannot be deleted, or nil if successful.
	DeleteUserByID(userID string) error

	// UpdateUser updates an existing user's information in the repository.
	//
	// Parameters:
	//
	//   user *User: The User object with updated information.
	//
	// Returns:
	//
	//   error: An error if the user cannot be updated, or nil if successful.
	UpdateUser(user *User) error

	// GetUserByUsername fetches a user by their username.
	//
	// Parameters:
	//
	//	username string: The username of the user to retrieve.
	//
	// Returns:
	//
	//	*User: The retrieved user, otherwise nil.
	GetUserByUsername(username string) *User

	// FindUnverifiedUsersOlderThanWeek retrieves users that have not been verified
	// and who's account has been created over a week ago.
	//
	// Returns:
	//
	//	[]*User: A slice of users.
	FindUnverifiedUsersOlderThanWeek() []*User
}
