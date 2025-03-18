package auth

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	loginAttempt "github.com/vigiloauth/vigilo/internal/auth/loginattempt"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// Authentication defines the interface for user authentication.
type Authentication interface {
	AuthenticateUser(loginUser *users.User, loginAttempt *loginAttempt.LoginAttempt) (*users.UserLoginResponse, error)
}

// Ensure AuthenticationService implements the Authentication interface.
var _ Authentication = (*AuthenticationService)(nil)

// AuthenticationService provides user authentication functionality.
type AuthenticationService struct {
	userStore         users.UserStore                // User data store.
	loginAttemptStore loginAttempt.LoginAttemptStore // Login attempt data store.
	config            *config.ServerConfig           // Server configuration.
	maxFailedAttempts int                            // Maximum failed login attempts.
	artificialDelay   time.Duration                  // Artificial delay for login attempts.
	tokenService      token.TokenService             // Token manager for JWT.
}

// NewAuthenticationService creates a new AuthenticationService instance.
//
// Parameters:
//
//	userStore users.UserStore: The user data store.
//	loginAttemptStore loginAttempt.LoginAttemptStore: The login attempt data store.
//	tokenService token.TokenService: The token service.
//
// Returns:
//
//	*AuthenticationService: A new AuthenticationService instance.
func NewAuthenticationService(userStore users.UserStore, loginAttemptStore loginAttempt.LoginAttemptStore, tokenService token.TokenService) *AuthenticationService {
	return &AuthenticationService{
		userStore:         userStore,
		loginAttemptStore: loginAttemptStore,
		config:            config.GetServerConfig(),
		tokenService:      tokenService,
		maxFailedAttempts: config.GetServerConfig().LoginConfig().MaxFailedAttempts(),
		artificialDelay:   config.GetServerConfig().LoginConfig().Delay(),
	}
}

// AuthenticateUser logs in a user and returns a token if successful.
// Each failed login attempt will be saved, and if the attempts exceed the threshold, the account will be locked.
//
// Parameters:
//
//	loginUser *users.User: The user attempting to log in.
//	loginAttempt *loginAttempt.LoginAttempt: The login attempt information.
//
// Returns:
//
//	*users.UserLoginResponse: The user login response containing user information and JWT token.
//	error: An error if authentication fails.
func (l *AuthenticationService) AuthenticateUser(loginUser *users.User, loginAttempt *loginAttempt.LoginAttempt) (*users.UserLoginResponse, error) {
	startTime := time.Now()
	defer l.applyArtificialDelay(startTime)

	retrievedUser := l.userStore.GetUser(loginUser.Email)
	if retrievedUser == nil {
		return nil, errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
	}

	if retrievedUser.AccountLocked {
		return nil, errors.New(errors.ErrCodeAccountLocked, "account is locked due to too many failed login attempts -- please reset your password")
	}

	loginAttempt.UserID = retrievedUser.ID
	if passwordsAreEqual := utils.ComparePasswordHash(loginUser.Password, retrievedUser.Password); !passwordsAreEqual {
		l.handleFailedLoginAttempt(retrievedUser, loginAttempt)
		return nil, errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
	}

	jwtToken, err := l.tokenService.GenerateToken(retrievedUser.Email, l.config.JWTConfig().ExpirationTime())
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeTokenCreation, "failed to create token")
	}

	retrievedUser.LastFailedLogin = time.Time{}
	if err := l.userStore.UpdateUser(retrievedUser); err != nil {
		return nil, errors.Wrap(err, "", "failed to update user")
	}

	return users.NewUserLoginResponse(retrievedUser, jwtToken), nil
}

// applyArtificialDelay applies an artificial delay to normalize response times.
//
// Parameters:
//
//	startTime time.Time: The start time of the login attempt.
func (l *AuthenticationService) applyArtificialDelay(startTime time.Time) {
	elapsed := time.Since(startTime)
	if elapsed < l.artificialDelay {
		time.Sleep(l.artificialDelay - elapsed)
	}
}

// handleFailedLoginAttempt handles a failed login attempt.
// It updates the user's last failed login time, saves the login attempt, and locks the account if necessary.
//
// Parameters:
//
//	retrievedUser *users.User: The user who attempted to log in.
//	loginAttempt *loginAttempt.LoginAttempt: The login attempt information.
//
// Returns:
//
//	error: An error if an operation fails.
func (l *AuthenticationService) handleFailedLoginAttempt(retrievedUser *users.User, loginAttempt *loginAttempt.LoginAttempt) error {
	retrievedUser.LastFailedLogin = time.Now()
	l.loginAttemptStore.SaveLoginAttempt(loginAttempt)
	if err := l.userStore.UpdateUser(retrievedUser); err != nil {
		return errors.Wrap(err, "", "failed to update user")
	}

	if l.shouldLockAccount(retrievedUser.ID) {
		if err := l.lockAccount(retrievedUser); err != nil {
			return errors.Wrap(err, "", err.Error())
		}
	}
	return nil
}

// shouldLockAccount checks if the account should be locked due to too many failed login attempts.
//
// Parameters:
//
//	userID string: The user ID.
//
// Returns:
//
//	bool: True if the account should be locked, false otherwise.
func (l *AuthenticationService) shouldLockAccount(userID string) bool {
	loginAttempts := l.loginAttemptStore.GetLoginAttempts(userID)
	return len(loginAttempts) >= l.maxFailedAttempts
}

// lockAccount locks the user account.
//
// Parameters:
//
//	retrievedUser *users.User: The user whose account should be locked.
//
// Returns:
//
//	error: An error if the update fails.
func (l *AuthenticationService) lockAccount(retrievedUser *users.User) error {
	retrievedUser.AccountLocked = true
	return l.userStore.UpdateUser(retrievedUser)
}
