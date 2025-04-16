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

	GetUserByUsername(username string) *User

	// HandleOAuthLogin authenticates a user based on an OAuth login request.
	//
	// This method constructs a User object and a UserLoginAttempt object from the provided
	// login request and request metadata, then delegates the authentication process
	// to the AuthenticateUser method.
	//
	// Parameters:
	//
	//   - request *UserLoginRequest: The login request containing the user's email and password.
	//   - clientID string: The client ID of the OAuth client making the request.
	//   - redirectURI string: The redirect URI to use if authentication is successful.
	//   - remoteAddr string: The remote address of the client making the request.
	//   - forwardedFor string: The value of the "X-Forwarded-For" header, if present.
	//   - userAgent string: The user agent string from the HTTP request.
	//
	// Returns:
	//
	//   - *UserLoginResponse: The response containing user information and a JWT token if authentication is successful.
	//   - error: An error if authentication fails or if the input is invalid.
	HandleOAuthLogin(request *UserLoginRequest, clientID, redirectURI, remoteAddr, forwardedFor, userAgent string) (*UserLoginResponse, error)

	// AuthenticateUserWithRequest authenticates a user based on a login request and request metadata.
	//
	// This method constructs a User object and a UserLoginAttempt object from the provided
	// login request and HTTP request metadata, then delegates the authentication process
	// to the AuthenticateUser method.
	//
	// Parameters:
	//
	//   - request *UserLoginRequest: The login request containing the user's email and password.
	//   - remoteAddr string: The remote address of the client making the request.
	//   - forwardedFor string: The value of the "X-Forwarded-For" header, if present.
	//   - userAgent string: The user agent string from the HTTP request.
	//
	// Returns:
	//
	//   - *UserLoginResponse: The response containing user information and a JWT token if authentication is successful.
	//   - error: An error if authentication fails or if the input is invalid.
	AuthenticateUserWithRequest(request *UserLoginRequest, remoteAddr, forwardedFor, userAgent string) (*UserLoginResponse, error)

	// AuthenticateUser authenticates a user based on their username and password.

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

	ValidateVerificationCode(verificationCode string) error
}
