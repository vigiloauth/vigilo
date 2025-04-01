package service

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	login "github.com/vigiloauth/vigilo/internal/domain/login"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
)

const module = "LoginService"

var logger = config.GetServerConfig().Logger()

type LoginAttemptServiceImpl struct {
	userRepo               user.UserRepository
	loginRepo              login.LoginAttemptRepository
	maxFailedLoginAttempts int
}

// NewLoginAttemptServiceImpl creates a new LoginServiceImpl instance.
//
// Parameters:
//
//	userRepo UserRepository: The user store to use.
//
// Returns:
//
//	*LoginServiceImpl: A new LoginServiceImpl instance.
func NewLoginAttemptServiceImpl(
	userRepo user.UserRepository,
	loginRepo login.LoginAttemptRepository,
) *LoginAttemptServiceImpl {
	return &LoginAttemptServiceImpl{
		userRepo:               userRepo,
		loginRepo:              loginRepo,
		maxFailedLoginAttempts: config.GetServerConfig().LoginConfig().MaxFailedAttempts(),
	}
}

// SaveLoginAttempt logs a login attempt.
//
// Parameters:
//
//	attempt *UserLoginAttempt: The login attempt to save.
func (s *LoginAttemptServiceImpl) SaveLoginAttempt(attempt *user.UserLoginAttempt) error {
	if err := s.loginRepo.SaveLoginAttempt(attempt); err != nil {
		logger.Error(module, "SaveLoginAttempt: Failed to save login attempt for user=[%s]: %v",
			common.TruncateSensitive(attempt.UserID), err,
		)
		return errors.Wrap(err, "", "failed to save login attempt")
	}
	return nil
}

// GetLoginAttempts retrieves all login attempts for a given user.
//
// Parameters:
//
//	userID string: The user ID.
//
// Returns:
//
//	[]*UserLoginAttempt: A slice of login attempts for the user.
func (s *LoginAttemptServiceImpl) GetLoginAttempts(userID string) []*user.UserLoginAttempt {
	return s.loginRepo.GetLoginAttempts(userID)
}

// HandleFailedLoginAttempt handles a failed login attempt.
// It updates the user's last failed login time, saves the login attempt, and locks the account if necessary.
//
// Parameters:
//
//	user *User: The user who attempted to log in.
//	attempt *LoginAttempt: The login attempt information.
//
// Returns:
//
//	error: An error if an operation fails.
func (s *LoginAttemptServiceImpl) HandleFailedLoginAttempt(user *user.User, attempt *user.UserLoginAttempt) error {
	logger.Info(module, "HandleFailedLoginAttempt: Authentication failed for user=[%s]", common.TruncateSensitive(user.ID))

	user.LastFailedLogin = time.Now()
	if err := s.loginRepo.SaveLoginAttempt(attempt); err != nil {
		logger.Error(module, "HandleFailedLoginAttempt: Failed to save login attempt for user=[%s]: %v",
			common.TruncateSensitive(attempt.UserID), err,
		)
		return errors.Wrap(err, "", "failed to save failed login attempt")
	}

	if err := s.userRepo.UpdateUser(user); err != nil {
		logger.Error(module, "HandleFailedLoginAttempt: Failed to update user=[%s]: %v", common.TruncateSensitive(user.ID), err)
		return errors.Wrap(err, "", "failed to update the user")
	}

	if s.shouldLockAccount(user.ID) {
		logger.Info(module, "HandleFailedLoginAttempt: Attempting to lock account for user=[%s]", common.TruncateSensitive(user.ID))
		if err := s.lockAccount(user); err != nil {
			logger.Error(module, "HandleFailedLoginAttempt: Failed to lock account for user=[%s]: %v", common.TruncateSensitive(user.ID), err)
			return errors.Wrap(err, "", "failed to update the user")
		}
		logger.Info(module, "HandleFailedLoginAttempt: Account successfully locked for user=[%s]", common.TruncateSensitive(user.ID))
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
func (s *LoginAttemptServiceImpl) shouldLockAccount(userID string) bool {
	loginAttempts := s.loginRepo.GetLoginAttempts(userID)
	return len(loginAttempts) >= s.maxFailedLoginAttempts
}

// lockAccount locks the user account.
//
// Parameters:
//
//	retrievedUser *User: The user whose account should be locked.
//
// Returns:
//
//	error: An error if the update fails.
func (s *LoginAttemptServiceImpl) lockAccount(retrievedUser *user.User) error {
	retrievedUser.AccountLocked = true
	return s.userRepo.UpdateUser(retrievedUser)
}
