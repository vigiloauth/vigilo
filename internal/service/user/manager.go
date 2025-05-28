package service

import (
	"context"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	crypto "github.com/vigiloauth/vigilo/v2/internal/domain/crypto"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ users.UserManager = (*userManager)(nil)

type userManager struct {
	repo          users.UserRepository
	parser        tokens.TokenParser
	manager       tokens.TokenManager
	cryptographer crypto.Cryptographer

	logger *config.Logger
	module string
}

func NewUserManager(
	repo users.UserRepository,
	parser tokens.TokenParser,
	manager tokens.TokenManager,
	cryptographer crypto.Cryptographer,
) users.UserManager {
	return &userManager{
		repo:          repo,
		parser:        parser,
		manager:       manager,
		cryptographer: cryptographer,

		logger: config.GetServerConfig().Logger(),
		module: "User Manager",
	}
}

// GetUserByUsername retrieves a user using their username.
//
// Parameter:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - username string: The username of the user to retrieve.
//
// Returns:
//   - *User: The retrieved user, otherwise nil.
//   - error: If an error occurs retrieving the user.
func (u *userManager) GetUserByUsername(ctx context.Context, username string) (*users.User, error) {
	requestID := utils.GetRequestID(ctx)

	user, err := u.repo.GetUserByUsername(ctx, username)
	if err != nil {
		u.logger.Error(u.module, requestID, "[GetUserByUsername]: Failed to get user by username: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve user")
	}

	return user, nil
}

// GetUserByID retrieves a user from the store using their ID.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The ID used to retrieve the user.
//
// Returns:
//   - *User: The User object if found, or nil if not found.
//   - error: If an error occurs retrieving the user.
func (u *userManager) GetUserByID(ctx context.Context, userID string) (*users.User, error) {
	requestID := utils.GetRequestID(ctx)

	user, err := u.repo.GetUserByID(ctx, userID)
	if err != nil {
		u.logger.Error(u.module, requestID, "[GetUserByID]: Failed to get user by ID: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve user")
	}

	return user, nil
}

// DeleteUnverifiedUsers deletes any user that hasn't verified their account and
// has been created for over a week.
//
// Parameter:
//   - ctx Context: The context for managing timeouts and cancellations.
//
// Returns:
//   - error: an error if deletion fails, otherwise nil.
func (u *userManager) DeleteUnverifiedUsers(ctx context.Context) error {
	requestID := utils.GetRequestID(ctx)

	unverifiedUsers, err := u.repo.FindUnverifiedUsersOlderThanWeek(ctx)
	if err != nil {
		u.logger.Error(u.module, requestID, "[DeleteUnverifiedUsers]: Failed to retrieve unverified users: %v", err)
		return errors.Wrap(err, "", "failed to retrieve unverified users")
	}

	for _, user := range unverifiedUsers {
		if err := u.repo.DeleteUserByID(ctx, user.ID); err != nil {
			u.logger.Error(u.module, requestID, "[DeleteUnverifiedUsers]: Failed to delete user by ID: %v", err)
			return errors.Wrap(err, "", "failed to delete user by ID")
		}
	}

	return nil
}

// ResetPassword resets the user's password using the provided reset token.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userEmail string: The user's email address.
//   - newPassword string: The new password.
//   - resetToken string: The reset token.
//
// Returns:
//   - *users.UserPasswordResetResponse: A response message.
//   - error: An error if the operation fails.
func (u *userManager) ResetPassword(
	ctx context.Context,
	userEmail string,
	newPassword string,
	resetToken string,
) (*users.UserPasswordResetResponse, error) {
	requestID := utils.GetRequestID(ctx)

	defer func() {
		if err := u.manager.BlacklistToken(ctx, resetToken); err != nil {
			u.logger.Error(u.module, requestID, "[ResetPassword]: Failed to blacklist reset token: %v", err)
		}
	}()

	user, err := u.repo.GetUserByEmail(ctx, userEmail)
	if err != nil {
		u.logger.Error(u.module, requestID, "[ResetPassword]: Failed to retrieve user: %v", err)
		return nil, errors.Wrap(err, "", "user not found")
	}

	parsedToken, err := u.parser.ParseToken(ctx, resetToken)
	if err != nil {
		u.logger.Error(u.module, requestID, "[ResetPassword]: Failed to parse reset token")
		return nil, errors.Wrap(err, "", "invalid reset token")
	}

	if user.ID != parsedToken.Subject {
		u.logger.Error(u.module, requestID, "[ResetPassword]: User ID does not match the token subject")
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid credentials")
	}

	encryptedPassword, err := u.cryptographer.HashString(newPassword)
	if err != nil {
		u.logger.Error(u.module, requestID, "[ResetPassword]: Failed to encrypt password: %v", err)
		return nil, errors.NewInternalServerError()
	}

	if user.AccountLocked {
		u.logger.Debug(u.module, requestID, "[ResetPassword]: Unlocking account for user=[%s]", (userEmail))
		user.AccountLocked = false
	}

	user.Password = encryptedPassword
	if err := u.repo.UpdateUser(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, "[ResetPassword]: Failed to update user: %v", err)
		return nil, errors.Wrap(err, "", "failed to update password")
	}

	return &users.UserPasswordResetResponse{
		Message: "Password has been reset successfully",
	}, nil
}
