package domain

import "context"

type UserService interface {
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

	// GetUserByUsername retrieves a user using their username.
	//
	// Parameter:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- username string: The username of the user to retrieve.
	//
	// Returns:
	//	- *User: The retrieved user, otherwise nil.
	//	- error: If an error occurs retrieving the user.
	GetUserByUsername(ctx context.Context, username string) (*User, error)

	// HandleOAuthLogin authenticates a user based on an OAuth login request.
	//
	// This method constructs a User object and a UserLoginAttempt object from the provided
	// login request and request metadata, then delegates the authentication process
	// to the AuthenticateUser method.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- request *UserLoginRequest: The login request containing the user's email and password.
	//	- clientID string: The client ID of the OAuth client making the request.
	//	- redirectURI string: The redirect URI to use if authentication is successful.
	//	- remoteAddr string: The remote address of the client making the request.
	//	- forwardedFor string: The value of the "X-Forwarded-For" header, if present.
	//	- userAgent string: The user agent string from the HTTP request.
	//
	// Returns:
	//	- *UserLoginResponse: The response containing user information and a JWT token if authentication is successful.
	//	- error: An error if authentication fails or if the input is invalid.
	HandleOAuthLogin(ctx context.Context, request *UserLoginRequest, clientID, redirectURI, remoteAddr, forwardedFor, userAgent string) (*UserLoginResponse, error)

	// AuthenticateUserWithRequest authenticates a user based on a login request and request metadata.
	//
	// This method constructs a User object and a UserLoginAttempt object from the provided
	// login request and HTTP request metadata, then delegates the authentication process
	// to the AuthenticateUser method.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- request *UserLoginRequest: The login request containing the user's email and password.
	//	- remoteAddr string: The remote address of the client making the request.
	//	- forwardedFor string: The value of the "X-Forwarded-For" header, if present.
	//	- userAgent string: The user agent string from the HTTP request.
	//
	// Returns:
	//	- *UserLoginResponse: The response containing user information and a JWT token if authentication is successful.
	//	- error: An error if authentication fails or if the input is invalid.
	AuthenticateUserWithRequest(ctx context.Context, request *UserLoginRequest, remoteAddr, forwardedFor, userAgent string) (*UserLoginResponse, error)

	// GetUserByID retrieves a user from the store using their ID.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The ID used to retrieve the user.
	//
	// Returns:
	//	- *User: The User object if found, or nil if not found.
	//	- error: If an error occurs retrieving the user.
	GetUserByID(ctx context.Context, userID string) (*User, error)

	// ValidateVerificationCode validates the verification code and updates the user
	// if verification was successful.
	//
	// Parameter:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- verificationCode string: The verification code to verify.
	//
	// Returns:
	//	- error: an error if validation fails, otherwise nil.
	ValidateVerificationCode(ctx context.Context, verificationCode string) error

	// DeleteUnverifiedUsers deletes any user that hasn't verified their account and
	// has been created for over a week.
	//
	// Parameter:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//
	// Returns:
	//	- error: an error if deletion fails, otherwise nil.
	DeleteUnverifiedUsers(ctx context.Context) error

	// ResetPassword resets the user's password using the provided reset token.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userEmail string: The user's email address.
	//	- newPassword string: The new password.
	//	- resetToken string: The reset token.
	//
	// Returns:
	//	- *users.UserPasswordResetResponse: A response message.
	//	- error: An error if the operation fails.
	ResetPassword(ctx context.Context, userEmail, newPassword, resetToken string) (*UserPasswordResetResponse, error)
}
