package users

// UserStore defines the interface for storing and managing user data.
type UserStore interface {
	// AddUser adds a new user to the store.
	//
	// Parameters:
	//   user *User: The User object to add.
	//
	// Returns:
	//   error: An error if the user cannot be added, or nil if successful.
	AddUser(user *User) error

	// GetUser retrieves a user from the store based on a value (e.g., ID, username, email).
	//
	// Parameters:
	//   value string: The value used to retrieve the user.
	//
	// Returns:
	//   *User: The User object if found, or nil if not found.
	GetUser(value string) *User

	// DeleteUser removes a user from the store based on a value (e.g., ID, username, email).
	//
	// Parameters:
	//   value string: The value used to identify the user to delete.
	//
	// Returns:
	//   error: An error if the user cannot be deleted, or nil if successful.
	DeleteUser(value string) error

	// UpdateUser updates an existing user's information in the store.
	//
	// Parameters:
	//   user *User: The User object with updated information.
	//
	// Returns:
	//   error: An error if the user cannot be updated, or nil if successful.
	UpdateUser(user *User) error
}
