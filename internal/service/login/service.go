package service

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	login "github.com/vigiloauth/vigilo/v2/internal/domain/login"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ login.LoginAttemptService = (*loginAttemptService)(nil)

type loginAttemptService struct {
	userRepo               user.UserRepository
	loginRepo              login.LoginAttemptRepository
	maxFailedLoginAttempts int

	logger *config.Logger
	module string
}

// NewLoginAttemptService creates a new LoginServiceImpl instance.
//
// Parameters:
//   - userRepo UserRepository: The user repository instance.
//   - loginRepo LoginRepository: The login repository instance.
//
// Returns:
//   - LoginAttemptService: A new LoginAttemptService instance.
func NewLoginAttemptService(
	userRepo user.UserRepository,
	loginRepo login.LoginAttemptRepository,
) login.LoginAttemptService {
	return &loginAttemptService{
		userRepo:               userRepo,
		loginRepo:              loginRepo,
		maxFailedLoginAttempts: config.GetServerConfig().LoginConfig().MaxFailedAttempts(),
		logger:                 config.GetServerConfig().Logger(),
		module:                 "Login Attempt Service",
	}
}

// SaveLoginAttempt logs a login attempt.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - attempt *UserLoginAttempt: The login attempt to save.
func (s *loginAttemptService) SaveLoginAttempt(ctx context.Context, attempt *user.UserLoginAttempt) error {
	requestID := utils.GetRequestID(ctx)
	if err := s.loginRepo.SaveLoginAttempt(ctx, attempt); err != nil {
		s.logger.Error(s.module, requestID, "[SaveLoginAttempt]: Failed to save login attempt for user=[%s]: %v",
			utils.TruncateSensitive(attempt.UserID), err,
		)
		return errors.Wrap(err, "", "failed to save login attempt")
	}
	return nil
}

// GetLoginAttemptsByUserID retrieves all login attempts for a given user.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The user ID.
//
// Returns:
//   - []*UserLoginAttempt: A slice of login attempts for the user.
//   - error: An error if retrieval fails.
func (s *loginAttemptService) GetLoginAttemptsByUserID(ctx context.Context, userID string) ([]*user.UserLoginAttempt, error) {
	requestID := utils.GetRequestID(ctx)
	attempts, err := s.loginRepo.GetLoginAttemptsByUserID(ctx, userID)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetLoginAttemptsByUserID]: An error occurred retrieving login attempts: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve user login attempts")
	}

	return attempts, nil
}

// HandleFailedLoginAttempt handles a failed login attempt.
// It updates the user's last failed login time, saves the login attempt, and locks the account if necessary.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - user *User: The user who attempted to log in.
//   - attempt *UserLoginAttempt: The login attempt information.
//
// Returns:
//   - error: An error if an operation fails.
func (s *loginAttemptService) HandleFailedLoginAttempt(ctx context.Context, user *user.User, attempt *user.UserLoginAttempt) error {
	requestID := utils.GetRequestID(ctx)
	s.logger.Info(s.module, requestID, "[HandleFailedLoginAttempt]: Authentication failed for user=[%s]", utils.TruncateSensitive(user.ID))

	user.LastFailedLogin = time.Now()
	if err := s.loginRepo.SaveLoginAttempt(ctx, attempt); err != nil {
		s.logger.Error(s.module, requestID, "[HandleFailedLoginAttempt]: Failed to save login attempt for user=[%s]: %v", utils.TruncateSensitive(attempt.UserID), err)
		return errors.Wrap(err, "", "failed to save failed login attempt")
	}

	if err := s.userRepo.UpdateUser(ctx, user); err != nil {
		s.logger.Error(s.module, requestID, "[HandleFailedLoginAttempt]: Failed to update user=[%s]: %v", utils.TruncateSensitive(user.ID), err)
		return errors.Wrap(err, "", "failed to update the user")
	}

	if s.shouldLockAccount(ctx, user.ID) {
		s.logger.Info(s.module, requestID, "[HandleFailedLoginAttempt]: Attempting to lock account for user=[%s]", utils.TruncateSensitive(user.ID))
		if err := s.lockAccount(ctx, user); err != nil {
			s.logger.Error(s.module, requestID, "[HandleFailedLoginAttempt]: Failed to lock account for user=[%s]: %v", utils.TruncateSensitive(user.ID), err)
			return errors.Wrap(err, "", "failed to update the user")
		}
		s.logger.Debug(s.module, requestID, "[HandleFailedLoginAttempt]: Account successfully locked for user=[%s]", utils.TruncateSensitive(user.ID))
	}

	return nil
}

func (s *loginAttemptService) shouldLockAccount(ctx context.Context, userID string) bool {
	requestID := utils.GetRequestID(ctx)
	loginAttempts, err := s.loginRepo.GetLoginAttemptsByUserID(ctx, userID)
	if err != nil {
		s.logger.Error(s.module, requestID, "An error occurred retrieving user login attempts: %v", err)
	}

	return len(loginAttempts) >= s.maxFailedLoginAttempts
}

func (s *loginAttemptService) lockAccount(ctx context.Context, retrievedUser *user.User) error {
	retrievedUser.AccountLocked = true
	return s.userRepo.UpdateUser(ctx, retrievedUser)
}
