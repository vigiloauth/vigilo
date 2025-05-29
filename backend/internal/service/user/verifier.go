package service

import (
	"context"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ users.UserVerifier = (*userVerifier)(nil)

type userVerifier struct {
	repo      users.UserRepository
	parser    tokens.TokenParser
	validator tokens.TokenValidator
	manager   tokens.TokenManager

	logger *config.Logger
	module string
}

func NewUserVerifier(
	repo users.UserRepository,
	parser tokens.TokenParser,
	validator tokens.TokenValidator,
	manager tokens.TokenManager,
) users.UserVerifier {
	return &userVerifier{
		repo:      repo,
		parser:    parser,
		validator: validator,
		manager:   manager,
		logger:    config.GetServerConfig().Logger(),
		module:    "User Verifier",
	}
}

// VerifyEmailAddress validates the verification code and marks the user's email as verified.
//
// Parameter:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - verificationCode string: The verification code to verify.
//
// Returns:
//   - error: an error if verification fails, otherwise nil.
func (u *userVerifier) VerifyEmailAddress(ctx context.Context, verificationCode string) error {
	requestID := utils.GetRequestID(ctx)

	defer func() {
		if err := u.manager.BlacklistToken(ctx, verificationCode); err != nil {
			u.logger.Error(u.module, requestID, "[VerifyEmailAddress]: Failed to blacklist verification code: %v", err)
		}
	}()

	if err := u.validator.ValidateToken(ctx, verificationCode); err != nil {
		u.logger.Error(u.module, requestID, "[VerifyEmailAddress]: Failed to validate verification code: %v", err)
		return errors.New(errors.ErrCodeUnauthorized, "the verification code either does not exist or is expired")
	}

	tokenClaims, err := u.parser.ParseToken(ctx, verificationCode)
	if err != nil {
		u.logger.Error(u.module, requestID, "[VerifyEmailAddress]: Failed to parse verification code: %v", err)
		return errors.Wrap(err, "", "failed to parse token")
	}

	user, err := u.repo.GetUserByID(ctx, tokenClaims.Subject)
	if err != nil {
		u.logger.Error(u.module, requestID, "[VerifyEmailAddress]: Failed to retrieve user by ID: %v", err)
		return errors.Wrap(err, errors.ErrCodeUnauthorized, "failed to retrieve user")
	}

	user.EmailVerified = true
	if err := u.repo.UpdateUser(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, "[VerifyEmailAddress]: Failed to update user")
		return errors.Wrap(err, "", "failed to update user")
	}

	return nil
}
