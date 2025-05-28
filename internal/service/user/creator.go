package service

import (
	"context"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	crypto "github.com/vigiloauth/vigilo/v2/internal/domain/crypto"
	emails "github.com/vigiloauth/vigilo/v2/internal/domain/email"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ users.UserCreator = (*userCreator)(nil)

type userCreator struct {
	repo          users.UserRepository
	issuer        tokens.TokenIssuer
	audit         audit.AuditLogger
	email         emails.EmailService
	cryptographer crypto.Cryptographer

	logger *config.Logger
	module string
}

func NewUserCreator(
	repo users.UserRepository,
	issuer tokens.TokenIssuer,
	audit audit.AuditLogger,
	email emails.EmailService,
	cryptographer crypto.Cryptographer,
) users.UserCreator {
	return &userCreator{
		repo:          repo,
		issuer:        issuer,
		audit:         audit,
		email:         email,
		cryptographer: cryptographer,
		logger:        config.GetServerConfig().Logger(),
		module:        "User Creator",
	}
}

// CreateUser creates a new user in the system.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - user *User: The user to register.
//
// Returns:
//   - *UserRegistrationResponse: The registered user object and an access token.
//   - error: An error if any occurred during the process.
func (u *userCreator) CreateUser(
	ctx context.Context,
	user *users.User,
) (res *users.UserRegistrationResponse, err error) {
	requestID := utils.GetRequestID(ctx)

	defer func() {
		if err != nil {
			u.audit.StoreEvent(ctx, audit.RegistrationAttempt, false, audit.RegistrationAction, audit.EmailMethod, err)
		} else {
			u.audit.StoreEvent(ctx, audit.RegistrationAttempt, true, audit.RegistrationAction, audit.EmailMethod, err)
		}
	}()

	encryptedPassword, err := u.cryptographer.HashString(user.Password)
	if err != nil {
		u.logger.Error(u.module, requestID, "[CreateUser]: Failed to encrypt password: %v", err)
		return nil, errors.Wrap(err, "", "failed to encrypt password")
	}

	user.Password = encryptedPassword
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	user.EmailVerified = false
	user.PhoneNumberVerified = false

	if user.HasRole(constants.AdminRole) {
		user.ID = constants.AdminRoleIDPrefix + utils.GenerateUUID()
	} else {
		user.ID = constants.UserRoleIDPrefix + utils.GenerateUUID()
	}

	if err := u.repo.AddUser(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, "[CreateUser]: Failed to save user: %v", err)
		return nil, errors.Wrap(err, "", "failed to save user")
	}

	accessToken, verificationCode, err := u.issuer.IssueTokenPair(
		ctx,
		user.Email,
		user.ID, "",
		strings.Join(user.Roles, " "),
		"", nil,
	)

	if err != nil {
		u.logger.Error(u.module, requestID, "[CreateUser]: Failed to generate verification code: %v", err)
		return nil, errors.Wrap(err, "", "failed to generate verification code")
	}

	emailRequest := emails.NewEmailRequest(user.Email, verificationCode, verificationCode, emails.AccountVerification)
	if err := u.email.SendEmail(ctx, emailRequest); err != nil {
		u.logger.Error(u.module, requestID, "[CreateUser]: Failed to send verification email: %v", err)
		return nil, errors.Wrap(err, "", "failed to send verification email")
	}

	return users.NewUserRegistrationResponse(user, accessToken), nil
}
