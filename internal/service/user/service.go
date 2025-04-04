package service

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/crypto"
	login "github.com/vigiloauth/vigilo/internal/domain/login"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ users.UserService = (*UserServiceImpl)(nil)
var logger = config.GetServerConfig().Logger()

const module = "User Service"

type UserServiceImpl struct {
	userRepo     users.UserRepository
	tokenService token.TokenService
	loginService login.LoginAttemptService

	jwtConfig       *config.TokenConfig
	artificialDelay time.Duration
}

// NewUserServiceImpl creates a new UserServiceImpl instance.
//
// Parameters:
//
//	userRepo UserRepository: The user repo to user.
//
// Returns:
//
//	*UserServiceImpl: A new UserServiceImpl instance.
func NewUserServiceImpl(
	userRepo users.UserRepository,
	tokenService token.TokenService,
	loginAttemptRepository login.LoginAttemptService,
) *UserServiceImpl {
	return &UserServiceImpl{
		userRepo:        userRepo,
		tokenService:    tokenService,
		loginService:    loginAttemptRepository,
		jwtConfig:       config.GetServerConfig().TokenConfig(),
		artificialDelay: config.GetServerConfig().LoginConfig().Delay(),
	}
}

// CreateUser creates a new user in the system.
//
// Parameters:
//
//	user *users.User: The user to register.
//
// Returns:
//
//	*users.UserRegistrationResponse: The registered user object and JWT token.
//	error: An error if any occurred during the process.
func (u *UserServiceImpl) CreateUser(user *users.User) (*users.UserRegistrationResponse, error) {
	hashedPassword, err := crypto.HashString(user.Password)
	if err != nil {
		logger.Error(module, "CreateUser: Failed to create new user: %v", err)
		return nil, errors.Wrap(err, "", "failed to encrypt password")
	}

	if existingUser := u.userRepo.GetUserByEmail(user.Email); existingUser != nil {
		err := errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided email")
		logger.Error(module, "CreateUser: Failed to create new user: %v", err)
		return nil, err
	}

	user.ID = crypto.GenerateUUID()
	user.Password = hashedPassword
	if err := u.userRepo.AddUser(user); err != nil {
		logger.Error(module, "CreateUser: Failed to create new user: %v", err)
		return nil, errors.Wrap(err, "", "failed to create new user")
	}

	jwtToken, err := u.tokenService.GenerateToken(user.Email, u.jwtConfig.ExpirationTime())
	if err != nil {
		logger.Error(module, "CreateUser: Failed to generate a session token: %v", err)
		return nil, errors.Wrap(err, "", "failed to generate session token")
	}

	return users.NewUserRegistrationResponse(user, jwtToken), nil
}

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
//   - redirectURI string: The redirect URI for the OAuth client.
//   - remoteAddr string: The remote address of the client making the request.
//   - forwardedFor string: The value of the "X-Forwarded-For" header, if present.
//   - userAgent string: The user agent string from the HTTP request.
//
// Returns:
//
//   - *UserLoginResponse: The response containing user information and a JWT token if authentication is successful.
//   - error: An error if authentication fails or if the input is invalid.
func (u *UserServiceImpl) HandleOAuthLogin(request *users.UserLoginRequest, clientID, redirectURI, remoteAddr, forwardedFor, userAgent string) (*users.UserLoginResponse, error) {
	if clientID == "" || redirectURI == "" {
		err := errors.New(errors.ErrCodeBadRequest, "missing one or more required parameters")
		logger.Error(module, "HandleOAuthLogin: Failed to login: %v", err)
		return nil, err
	}

	if err := request.Validate(); err != nil {
		logger.Error(module, "HandleOAuthLogin: Failed to validate request: %v", err)
		return nil, err
	}

	response, err := u.AuthenticateUserWithRequest(request, remoteAddr, forwardedFor, userAgent)
	if err != nil {
		logger.Error(module, "HandleOAuthLogin: Failed to authenticate user: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeUnauthorized, "failed to authenticate user")
	}

	return response, nil
}

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
func (u *UserServiceImpl) AuthenticateUserWithRequest(request *users.UserLoginRequest, remoteAddr, forwardedFor, userAgent string) (*users.UserLoginResponse, error) {
	user := &users.User{
		ID:       request.ID,
		Email:    request.Email,
		Password: request.Password,
	}

	loginAttempt := users.NewUserLoginAttempt(remoteAddr, forwardedFor, "", userAgent)
	logger.Info(module, "AuthenticateUserWithRequest: Authenticating user=[%s] for remoteAddr=[%s], forwardedFor=[%s], userAgent=[%s]",
		common.TruncateSensitive(user.Email),
		common.TruncateSensitive(remoteAddr),
		forwardedFor, userAgent,
	)
	return u.authenticateUser(user, loginAttempt)
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
func (u *UserServiceImpl) GetUserByID(userID string) *users.User {
	return u.userRepo.GetUserByID(userID)
}

// applyArtificialDelay applies an artificial delay to normalize response times.
//
// Parameters:
//
//	startTime time.Time: The start time of the login attempt.
func (u *UserServiceImpl) applyArtificialDelay(startTime time.Time) {
	elapsed := time.Since(startTime)
	if elapsed < u.artificialDelay {
		time.Sleep(u.artificialDelay - elapsed)
	}
}

// authenticateUser logs in a user and returns a token if successful.
// Each failed login attempt will be saved, and if the attempts exceed the threshold, the account will be locked.
//
// Parameters:
//
//	loginUser *users.User: The user attempting to log in.
//	loginAttempt *users.LoginAttempt: The login attempt information.
//
// Returns:
//
//	*users.UserLoginResponse: The user login response containing user information and JWT token.
//	error: An error if authentication fails.
func (u *UserServiceImpl) authenticateUser(
	loginUser *users.User,
	loginAttempt *users.UserLoginAttempt,
) (*users.UserLoginResponse, error) {
	startTime := time.Now()
	defer u.applyArtificialDelay(startTime)

	retrievedUser := u.userRepo.GetUserByID(loginUser.ID)
	if retrievedUser == nil {
		err := errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
		logger.Error(module, "Failed to retrieve user by ID=[%s]: %v", common.TruncateSensitive(loginUser.ID), err)
		return nil, err
	}

	if retrievedUser.AccountLocked {
		err := errors.New(
			errors.ErrCodeAccountLocked,
			"account is locked due to too many failed login attempts -- please reset your password",
		)
		logger.Error(module, "Failed to authenticate due to too many failed attempts=[%d], timestamp=[%s]", loginAttempt.FailedAttempts, loginAttempt.Timestamp)
		return nil, err
	}

	loginAttempt.UserID = retrievedUser.ID
	if passwordsAreEqual := crypto.CompareHash(loginUser.Password, retrievedUser.Password); !passwordsAreEqual {
		logger.Error(module, "Failed to compare passwords. Passwords do not match")
		if err := u.loginService.HandleFailedLoginAttempt(retrievedUser, loginAttempt); err != nil {
			return nil, errors.NewInternalServerError()
		}

		err := errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
		logger.Error(module, "Failed to authenticate user=[%s]: %v", common.TruncateSensitive(loginUser.ID), err)
		return nil, err
	}

	jwtToken, err := u.tokenService.GenerateToken(retrievedUser.ID, u.jwtConfig.ExpirationTime())
	if err != nil {
		logger.Error(module, "Failed to generate access token for user=[%s]: %v", common.TruncateSensitive(retrievedUser.ID), err)
		return nil, errors.NewInternalServerError()
	}

	retrievedUser.LastFailedLogin = time.Time{}
	if err := u.userRepo.UpdateUser(retrievedUser); err != nil {
		logger.Error(module, "Failed to update user after successful authentication: %v", err)
		return nil, errors.Wrap(err, "", "failed to update user")
	}

	logger.Info(module, "User Authentication successful")
	return users.NewUserLoginResponse(retrievedUser, jwtToken), nil
}
