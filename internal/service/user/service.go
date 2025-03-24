package service

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/crypto"
	login "github.com/vigiloauth/vigilo/internal/domain/login"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ users.UserService = (*UserServiceImpl)(nil)

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
		return nil, errors.Wrap(err, "", "failed to encrypt password")
	}

	if existingUser := u.userRepo.GetUserByID(user.Email); existingUser != nil {
		return nil, errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided email")
	}

	user.ID = crypto.GenerateUUID()
	user.Password = hashedPassword
	if err := u.userRepo.AddUser(user); err != nil {
		return nil, errors.Wrap(err, "", "failed to create new user")
	}

	jwtToken, err := u.tokenService.GenerateToken(user.Email, u.jwtConfig.ExpirationTime())
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to generate session token")
	}

	return users.NewUserRegistrationResponse(user, jwtToken), nil
}

// AuthenticateUser logs in a user and returns a token if successful.
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
func (u *UserServiceImpl) AuthenticateUser(
	loginUser *users.User,
	loginAttempt *users.UserLoginAttempt,
) (*users.UserLoginResponse, error) {
	startTime := time.Now()
	defer u.applyArtificialDelay(startTime)

	retrievedUser := u.userRepo.GetUserByID(loginUser.ID)
	if retrievedUser == nil {
		return nil, errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
	}

	if retrievedUser.AccountLocked {
		return nil, errors.New(
			errors.ErrCodeAccountLocked,
			"account is locked due to too many failed login attempts -- please reset your password",
		)
	}

	loginAttempt.UserID = retrievedUser.ID
	if passwordsAreEqual := crypto.CompareHash(loginUser.Password, retrievedUser.Password); !passwordsAreEqual {
		if err := u.loginService.HandleFailedLoginAttempt(retrievedUser, loginAttempt); err != nil {
			return nil, errors.NewInternalServerError()
		}

		return nil, errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
	}

	jwtToken, err := u.tokenService.GenerateToken(retrievedUser.ID, u.jwtConfig.ExpirationTime())
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeTokenCreation, "failed to create token")
	}

	retrievedUser.LastFailedLogin = time.Time{}
	if err := u.userRepo.UpdateUser(retrievedUser); err != nil {
		return nil, errors.Wrap(err, "", "failed to update user")
	}

	return users.NewUserLoginResponse(retrievedUser, jwtToken), nil
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
