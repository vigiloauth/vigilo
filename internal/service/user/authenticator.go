package service

import (
	"context"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	login "github.com/vigiloauth/vigilo/v2/internal/domain/login"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ users.UserAuthenticator = (*userAuthenticator)(nil)

type RequestMetadata struct {
	IPAddress string
	UserAgent string
}

type userAuthenticator struct {
	repo                users.UserRepository
	auditLogger         audit.AuditLogger
	loginAttemptService login.LoginAttemptService
	tokenIssuer         tokens.TokenIssuer

	artificialDelay                 time.Duration
	maxFailedAuthenticationAttempts int
	logger                          *config.Logger
	module                          string
}

func NewUserAuthenticator(
	repo users.UserRepository,
	auditLogger audit.AuditLogger,
	loginAttemptService login.LoginAttemptService,
	tokenIssuer tokens.TokenIssuer,
) users.UserAuthenticator {
	return &userAuthenticator{
		repo:                            repo,
		auditLogger:                     auditLogger,
		loginAttemptService:             loginAttemptService,
		tokenIssuer:                     tokenIssuer,
		artificialDelay:                 config.GetServerConfig().LoginConfig().Delay(),
		maxFailedAuthenticationAttempts: config.GetServerConfig().LoginConfig().MaxFailedAttempts(),
		logger:                          config.GetServerConfig().Logger(),
		module:                          "User Authenticator",
	}
}

// AuthenticateUserWithRequest authenticates a user based on a login request and request metadata.
//
// This method constructs a User object and a UserLoginAttempt object from the provided
// login request and HTTP request metadata, then delegates the authentication process
// to the AuthenticateUser method.
//
// Parameters:
//   - ctx Context: The context for managing timeouts, cancellations, and for retrieving/storing request metadata.
//   - request *UserLoginRequest: The login request containing the user's email and password.
//
// Returns:
//   - *UserLoginResponse: The response containing user information and a JWT token if authentication is successful.
//   - error: An error if authentication fails or if the input is invalid.
func (u *userAuthenticator) AuthenticateUser(
	ctx context.Context,
	request *users.UserLoginRequest,
) (res *users.UserLoginResponse, err error) {
	requestID := utils.GetRequestID(ctx)
	startTime := time.Now()
	defer u.applyArtificialDelay(startTime)

	requestMetadata := u.extractMetadataFromContext(ctx)
	loginAttempt := &users.UserLoginAttempt{
		Timestamp: time.Now().UTC(),
		IPAddress: requestMetadata.IPAddress,
		UserAgent: requestMetadata.UserAgent,
	}

	user, err := u.repo.GetUserByUsername(ctx, request.Username)
	if err != nil {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: Failed to retrieve user by username: %v", err)
		u.logAuthenticationAttempt(ctx, false, err, "")

		return nil, errors.Wrap(err, errors.ErrCodeInvalidCredentials, "username or password are incorrect")
	}

	defer func() {
		var userID string
		if user != nil {
			userID = user.ID
		}
		if err != nil {
			u.logAuthenticationAttempt(ctx, false, err, userID)
		} else {
			u.logAuthenticationAttempt(ctx, true, err, userID)
		}
	}()

	loginAttempt.UserID = user.ID

	defer func() {
		if err != nil {
			if err := u.loginAttemptService.HandleFailedLoginAttempt(ctx, user, loginAttempt); err != nil {
				u.logger.Error(u.module, requestID, "[AuthenticateUser]: An error occurred while handling the failed auth attempt: %v", err)
			}
		}
	}()

	if user.AccountLocked {
		err := errors.New(errors.ErrCodeAccountLocked, "account has been locked due to too many failed attempts")
		u.logAuthenticationAttempt(ctx, false, err, user.ID)

		return nil, err
	}

	if err := u.comparePasswords(request.Password, user.Password); err != nil {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: Failed to compare passwords: %v", err)
		u.logAuthenticationAttempt(ctx, false, err, user.ID)
		return nil, errors.Wrap(err, "", "failed to authenticate user")
	}

	user.LastFailedLogin = time.Time{}
	if err := u.repo.UpdateUser(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: Failed to update user: %v", err)
		u.logAuthenticationAttempt(ctx, false, err, user.ID)
		return nil, errors.Wrap(err, "", "failed to update user")
	}

	if err := u.loginAttemptService.SaveLoginAttempt(ctx, loginAttempt); err != nil {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: Failed to save authentication attempt: %v", err)
		return nil, errors.Wrap(err, "", "failed to save authentication attempt")
	}

	roles := strings.Join(user.Roles, ", ")
	accessToken, refreshToken, err := u.tokenIssuer.IssueTokenPair(ctx, user.ID, "", "", roles, "", nil)
	if err != nil {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: Failed to generate tokens: %v", err)
		return nil, errors.Wrap(err, "", "failed to generate tokens")
	}

	u.logAuthenticationAttempt(ctx, true, nil, user.ID)

	return users.NewUserLoginResponse(user, accessToken, refreshToken), nil
}

func (u *userAuthenticator) applyArtificialDelay(startTime time.Time) {
	elapsed := time.Since(startTime)
	if elapsed < u.artificialDelay {
		time.Sleep(u.artificialDelay - elapsed)
	}
}

func (u *userAuthenticator) logAuthenticationAttempt(ctx context.Context, success bool, err error, userID string) {
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserID, userID)
	u.auditLogger.StoreEvent(ctx, audit.LoginAttempt, success, audit.AuthenticationAction, audit.OAuthMethod, err)
}

func (u *userAuthenticator) comparePasswords(password string, hashedPassword string) error {
	passwordsAreEqual := utils.CompareHash(password, hashedPassword)
	if !passwordsAreEqual {
		return errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
	}

	return nil
}

func (u *userAuthenticator) extractMetadataFromContext(ctx context.Context) RequestMetadata {
	var requestMetadata RequestMetadata

	if IP := utils.GetValueFromContext(ctx, constants.ContextKeyIPAddress); IP != "" {
		requestMetadata.IPAddress, _ = IP.(string)
	}

	if userAgent := utils.GetValueFromContext(ctx, constants.ContextKeyUserAgent); userAgent != "" {
		requestMetadata.UserAgent, _ = userAgent.(string)
	}

	return requestMetadata
}
