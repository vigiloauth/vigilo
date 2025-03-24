package domain

type UserService interface {
	// CreateUser creates a new user in the system.
	//
	// Parameters:
	//
	//	user *User: The user to register.
	//
	// Returns:
	//
	//	*UserRegistrationResponse: The registered user object and JWT token.
	//	error: An error if any occurred during the process.
	CreateUser(user *User) (*UserRegistrationResponse, error)

	// AuthenticateUser logs in a user and returns a token if successful.
	// Each failed login attempt will be saved, and if the attempts exceed the threshold, the account will be locked.
	//
	// Parameters:
	//
	//	loginUser *User: The user attempting to log in.
	//	loginAttempt *LoginAttempt: The login attempt information.
	//
	// Returns:
	//
	//	*UserLoginResponse: The user login response containing user information and JWT token.
	//	error: An error if authentication fails.
	AuthenticateUser(loginUser *User, loginAttempt *UserLoginAttempt) (*UserLoginResponse, error)

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
}
