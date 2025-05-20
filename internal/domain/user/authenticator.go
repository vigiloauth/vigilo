package domain

import "context"

type UserAuthenticator interface {
	// AuthenticateUserWithRequest authenticates a user based on a login request and request metadata.
	//
	// This method constructs a User object and a UserLoginAttempt object from the provided
	// login request and HTTP request metadata, then delegates the authentication process
	// to the AuthenticateUser method.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts, cancellations, and for retrieving/storing request metadata.
	//   - request *UserLoginRequest: The login request containing the user's email and password.
	//
	// Returns:
	//   - *UserLoginResponse: The response containing user information and a JWT token if authentication is successful.
	//   - error: An error if authentication fails or if the input is invalid.
	AuthenticateUser(ctx context.Context, request *UserLoginRequest) (*UserLoginResponse, error)

	// HandleFailedAuthenticationAttempt handles a failed login attempt.
	// It updates the user's last failed login time, saves the login attempt, and locks the account if necessary.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - user *User: The user who attempted to log in.
	//   - attempt *UserLoginAttempt: The login attempt information.
	//
	// Returns:
	//   - error: An error if an operation fails.
	HandleFailedAuthenticationAttempt(ctx context.Context, user *User, attempt *UserLoginAttempt) error
}
