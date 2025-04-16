package service

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/crypto"
	email "github.com/vigiloauth/vigilo/internal/domain/email"
	login "github.com/vigiloauth/vigilo/internal/domain/login"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ users.UserService = (*userService)(nil)

type userService struct {
	userRepo     users.UserRepository
	tokenService token.TokenService
	loginService login.LoginAttemptService
	emailService email.EmailService

	jwtConfig       *config.TokenConfig
	artificialDelay time.Duration
	logger          *config.Logger
	module          string
}

// NewUserService creates a new UserServiceImpl instance.
//
// Parameters:
//
//	userRepo UserRepository: The user repo to user.
//
// Returns:
//
//	*UserServiceImpl: A new UserServiceImpl instance.
func NewUserService(
	userRepo users.UserRepository,
	tokenService token.TokenService,
	loginAttemptRepository login.LoginAttemptService,
	emailService email.EmailService,
) users.UserService {
	return &userService{
		userRepo:        userRepo,
		tokenService:    tokenService,
		loginService:    loginAttemptRepository,
		emailService:    emailService,
		jwtConfig:       config.GetServerConfig().TokenConfig(),
		artificialDelay: config.GetServerConfig().LoginConfig().Delay(),
		logger:          config.GetServerConfig().Logger(),
		module:          "User Service",
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
func (u *userService) CreateUser(user *users.User) (*users.UserRegistrationResponse, error) {
	if u.userExistsByEmail(user.Email) {
		err := errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided email")
		u.logger.Error(u.module, "[CreateUser]: Failed to create new user: %v", err)
		return nil, err
	}

	if err := u.saveUser(user); err != nil {
		u.logger.Error(u.module, "[CreateUser]: Failed to save user: %v", err)
		return nil, err
	}

	if err := u.sendVerificationEmail(user); err != nil {
		u.logger.Error(u.module, "[CreateUser]: Failed to send account verification email: %v", err)
		return nil, nil
	}

	accessToken, err := u.tokenService.GenerateToken(user.Email, "", u.jwtConfig.ExpirationTime())
	if err != nil {
		u.logger.Error(u.module, "[CreateUser]: Failed to generate a session token: %v", err)
		return nil, errors.Wrap(err, "", "failed to generate session token")
	}

	return users.NewUserRegistrationResponse(user, accessToken), nil
}

// GetUserByUsername retrieves a user using their username.
//
// Parameter:
//
//	username string: The username of the user to retrieve.
//
// Returns:
//
//	*User: The retrieved user, otherwise nil.
func (u *userService) GetUserByUsername(username string) *users.User {
	return u.userRepo.GetUserByUsername(username)
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
func (u *userService) HandleOAuthLogin(request *users.UserLoginRequest, clientID, redirectURI, remoteAddr, forwardedFor, userAgent string) (*users.UserLoginResponse, error) {
	if err := request.Validate(); err != nil {
		u.logger.Error(u.module, "[HandleOAuthLogin]: Failed to validate request: %v", err)
		return nil, err
	}

	response, err := u.AuthenticateUserWithRequest(request, remoteAddr, forwardedFor, userAgent)
	if err != nil {
		u.logger.Error(u.module, "[HandleOAuthLogin]: Failed to authenticate user: %v", err)
		return nil, errors.New(errors.ErrCodeUnauthorized, "credentials are either missing or invalid")
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
func (u *userService) AuthenticateUserWithRequest(request *users.UserLoginRequest, remoteAddr, forwardedFor, userAgent string) (*users.UserLoginResponse, error) {
	user := &users.User{
		ID:       request.ID,
		Username: request.Username,
		Password: request.Password,
	}

	loginAttempt := users.NewUserLoginAttempt(remoteAddr, forwardedFor, "", userAgent)
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
func (u *userService) GetUserByID(userID string) *users.User {
	return u.userRepo.GetUserByID(userID)
}

// ValidateVerificationCode validates the verification code and updates the user
// if verification was successful.
//
// Parameter:
//
//	verificationCode string: The verification code to verify.
//
// Returns:
//
//	error: an error if validation fails, otherwise nil.
func (u *userService) ValidateVerificationCode(verificationCode string) error {
	if verificationCode == "" {
		return errors.New(errors.ErrCodeInvalidRequest, "missing one or more required parameters in the request")
	}

	if err := u.tokenService.ValidateToken(verificationCode); err != nil {
		u.logger.Error(u.module, "[ValidateVerificationCode]: Failed to validate verification code: %v", err)
		return errors.New(errors.ErrCodeUnauthorized, "the verification code is either expired or does not exist")
	}

	claims, err := u.tokenService.ParseToken(verificationCode)
	if err != nil {
		u.logger.Error(u.module, "[ValidateVerificationCode]: Failed to parse verification code: %v", err)
		return errors.NewInternalServerError()
	}

	user := u.userRepo.GetUserByEmail(claims.Subject)
	if user == nil {
		return errors.New(errors.ErrCodeUnauthorized, "the verification code is invalid")
	}

	if user.Verified {
		return nil
	}

	user.Verified = true
	if err := u.updateAuthenticatedUser(user); err != nil {
		return err
	}

	return nil
}

// DeleteUnverifiedUsers deletes any user that hasn't verified their account and
// has been created for over a week.
func (u *userService) DeleteUnverifiedUsers() {
	expiredUsers := u.userRepo.FindUnverifiedUsersOlderThanWeek()
	for _, user := range expiredUsers {
		u.userRepo.DeleteUserByID(user.ID)
	}
}

// applyArtificialDelay applies an artificial delay to normalize response times.
//
// Parameters:
//
//	startTime time.Time: The start time of the login attempt.
func (u *userService) applyArtificialDelay(startTime time.Time) {
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
func (u *userService) authenticateUser(loginUser *users.User, loginAttempt *users.UserLoginAttempt) (*users.UserLoginResponse, error) {
	startTime := time.Now()
	defer u.applyArtificialDelay(startTime)

	retrievedUser := u.userRepo.GetUserByID(loginUser.ID)
	if retrievedUser == nil {
		err := errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
		u.logger.Error(u.module, "Failed to retrieve user by ID=[%s]: %v", common.TruncateSensitive(loginUser.ID), err)
		return nil, err
	}

	if retrievedUser.AccountLocked {
		err := errors.New(errors.ErrCodeAccountLocked, "account is locked due to too many failed login attempts -- please reset your password")
		u.logger.Error(u.module, "Failed to authenticate due to too many failed attempts=[%d], timestamp=[%s]", loginAttempt.FailedAttempts, loginAttempt.Timestamp)
		return nil, err
	}

	if err := u.comparePasswords(loginUser, retrievedUser, loginAttempt); err != nil {
		return nil, errors.Wrap(err, "", "failed to authenticate user")
	}

	accessToken, err := u.tokenService.GenerateToken(retrievedUser.ID, "", u.jwtConfig.ExpirationTime())
	if err != nil {
		u.logger.Error(u.module, "Failed to generate access token for user=[%s]: %v", common.TruncateSensitive(retrievedUser.ID), err)
		return nil, errors.NewInternalServerError()
	}

	retrievedUser.LastFailedLogin = time.Time{}
	if err := u.updateAuthenticatedUser(retrievedUser); err != nil {
		u.logger.Error(u.module, "Failed to update authenticated user: %v", err)
		return nil, err
	}

	return users.NewUserLoginResponse(retrievedUser, accessToken), nil
}

func (u *userService) updateAuthenticatedUser(user *users.User) error {
	if err := u.userRepo.UpdateUser(user); err != nil {
		u.logger.Error(u.module, "Failed to update user after successful authentication: %v", err)
		return errors.Wrap(err, "", "failed to update user")
	}

	return nil
}

func (u *userService) comparePasswords(loginUser *users.User, existingUser *users.User, loginAttempt *users.UserLoginAttempt) error {
	loginAttempt.UserID = existingUser.ID
	if passwordsAreEqual := crypto.CompareHash(loginUser.Password, existingUser.Password); !passwordsAreEqual {
		u.logger.Error(u.module, "Failed to compare passwords. Passwords do not match")
		if err := u.loginService.HandleFailedLoginAttempt(existingUser, loginAttempt); err != nil {
			return errors.NewInternalServerError()
		}

		err := errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
		u.logger.Error(u.module, "Failed to authenticate user=[%s]: %v", common.TruncateSensitive(loginUser.ID), err)
		return err
	}

	return nil
}

func (u *userService) userExistsByEmail(email string) bool {
	return u.userRepo.GetUserByEmail(email) != nil
}

func (u *userService) encryptPassword(user *users.User) error {
	hashedPassword, err := crypto.HashString(user.Password)
	if err != nil {
		u.logger.Error(u.module, "Failed to encrypt: %v", err)
		return errors.Wrap(err, "", "failed to encrypt password")
	}

	user.Password = hashedPassword
	return nil
}

func (u *userService) saveUser(user *users.User) error {
	if err := u.encryptPassword(user); err != nil {
		u.logger.Error(u.module, "[CreateUser]: Failed to create new user: %v", err)
		return errors.NewInternalServerError()
	}

	user.CreatedAt = time.Now()
	user.ID = crypto.GenerateUUID()
	if err := u.userRepo.AddUser(user); err != nil {
		u.logger.Error(u.module, "Failed to save user: %v", err)
		return errors.NewInternalServerError()
	}

	return nil
}

func (u *userService) sendVerificationEmail(user *users.User) error {
	verificationCode, err := u.tokenService.GenerateToken(user.Email, "", u.jwtConfig.AccessTokenDuration())
	if err != nil {
		u.logger.Error(u.module, "Failed to generate verification code: %v", err)
		return err
	}

	emailRequest := email.NewEmailRequest(user.Email, verificationCode, verificationCode, email.AccountVerification)
	return u.emailService.SendEmail(emailRequest)
}
