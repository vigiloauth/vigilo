package domain

import "context"

type UserCreator interface {
	// CreateUser creates a new user in the system.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- user *User: The user to register.
	//
	// Returns:
	//	- *UserRegistrationResponse: The registered user object and an access token.
	//	- error: An error if any occurred during the process.
	CreateUser(ctx context.Context, user *User) (*UserRegistrationResponse, error)
}
