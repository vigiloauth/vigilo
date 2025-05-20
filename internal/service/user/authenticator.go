package service

import (
	"context"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	login "github.com/vigiloauth/vigilo/v2/internal/domain/login"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ users.UserAuthenticator = (*userAuthenticator)(nil)

type userAuthenticator struct {
	repo                            users.UserRepository
	auditLogger                     audit.AuditLogger
	loginAttemptRepo                login.LoginAttemptRepository
	tokenIssuer                     token.TokenIssuer
	artificialDelay                 time.Duration
	maxFailedAuthenticationAttempts int
	logger                          *config.Logger
	module                          string
}

func NewUserAuthenticator(
	repo users.UserRepository,
	auditLogger audit.AuditLogger,
	loginAttemptRepo login.LoginAttemptRepository,
	tokenIssuer token.TokenIssuer,
) users.UserAuthenticator {
	return &userAuthenticator{
		repo:                            repo,
		auditLogger:                     auditLogger,
		loginAttemptRepo:                loginAttemptRepo,
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
) (resp *users.UserLoginResponse, err error) {
	startTime := time.Now()
	defer u.applyArtificialDelay(startTime)
	requestID := utils.GetRequestID(ctx)

	loginAttempt := &users.UserLoginAttempt{
		Timestamp:      time.Now().UTC(),
		FailedAttempts: 0,
	}

	if IP := utils.GetValueFromContext(ctx, constants.ContextKeyIPAddress); IP != nil {
		loginAttempt.IPAddress, _ = IP.(string)
	} else {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: There was an error retrieving the IP address from context")
		err = errors.NewInternalServerError()
		return
	}

	if userAgent := utils.GetValueFromContext(ctx, constants.ContextKeyUserAgent); userAgent != nil {
		loginAttempt.UserAgent, _ = userAgent.(string)
	} else {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: There was an error retrieving the user agent from context")
		err = errors.NewInternalServerError()
		return
	}

	retrievedUser, err := u.repo.GetUserByUsername(ctx, request.Username)
	if err != nil {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: An error occurred retrieving the user by username: %v", err)
		err = errors.Wrap(err, "", "username or password are incorrect")
		return
	}

	defer func() {
		if err != nil && retrievedUser != nil {
			u.HandleFailedAuthenticationAttempt(ctx, retrievedUser, loginAttempt)
			u.logAuthenticationAttempt(ctx, false, err, retrievedUser.ID)
		} else {
			u.logAuthenticationAttempt(ctx, true, nil, retrievedUser.ID)
		}
	}()

	loginAttempt.UserID = retrievedUser.ID
	if retrievedUser.AccountLocked {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: Failed to authenticate due to too many failed attempts=[%d], timestamp=[%s]", loginAttempt.FailedAttempts, loginAttempt.Timestamp)
		err = errors.New(errors.ErrCodeAccountLocked, "account has been locked due to too may failed login attempts")
		return
	}

	if err = u.comparePassword(request, retrievedUser); err != nil {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: Failed to compare password: %v", err)
		err = errors.Wrap(err, "", "failed to authenticate user")
		return
	}

	roles := strings.Join(retrievedUser.Roles, " ")
	accessToken, refreshToken, err := u.tokenIssuer.IssueTokenPair(
		ctx, retrievedUser.Email,
		retrievedUser.ID, "",
		roles, "", nil,
	)

	if err != nil {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: Failed to issue token pair: %v", err)
		err = errors.NewInternalServerError()
		return
	}

	retrievedUser.LastFailedLogin = time.Time{}
	if err = u.repo.UpdateUser(ctx, retrievedUser); err != nil {
		u.logger.Error(u.module, requestID, "[AuthenticateUser]: Failed to update authenticated user: %v", err)
		err = errors.Wrap(err, "", "failed to update user")
		return
	}

	resp = users.NewUserLoginResponse(retrievedUser, accessToken, refreshToken)
	return
}

// HandleFailedAuthenticationAttempt handles a failed login attempt.
// It updates the user's last failed login time, saves the login attempt, and locks the account if necessary.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - user *User: The user who attempted to log in.
//   - attempt *UserLoginAttempt: The login attempt information.
//
// Returns:
//   - error: An error if an operation fails.
func (u *userAuthenticator) HandleFailedAuthenticationAttempt(
	ctx context.Context,
	user *users.User,
	attempt *users.UserLoginAttempt,
) error {
	requestID := utils.GetRequestID(ctx)

	user.LastFailedLogin = time.Now()
	if err := u.loginAttemptRepo.SaveLoginAttempt(ctx, attempt); err != nil {
		u.logger.Error(u.module, requestID, "[HandleFailedAuthenticationAttempt]: Failed to save login attempt for user=[%s]: %v", utils.TruncateSensitive(attempt.UserID), err)
		return errors.Wrap(err, "", "failed to save failed login attempt")
	}

	if err := u.repo.UpdateUser(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, "[HandleFailedAuthenticationAttempt]: Failed to update user: %v", err)
		return errors.Wrap(err, "", "failed to update the user")
	}

	if u.shouldLockAccount(ctx, user.ID) {
		if err := u.lockAccount(ctx, user); err != nil {
			u.logger.Error(u.module, requestID, "[HandleFailedAuthenticationAttempt]: Failed to lock user's account: %v", err)
			return errors.Wrap(err, "", "failed to lock account")
		}
	}

	return nil
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

func (u *userAuthenticator) comparePassword(
	request *users.UserLoginRequest,
	existingUser *users.User,
) error {
	passwordsAreEqual := crypto.CompareHash(
		request.Password,
		existingUser.Password,
	)

	if !passwordsAreEqual {
		return errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
	}

	return nil
}

func (u *userAuthenticator) shouldLockAccount(ctx context.Context, userID string) bool {
	requestID := utils.GetRequestID(ctx)

	userLoginAttempts, err := u.loginAttemptRepo.GetLoginAttemptsByUserID(ctx, userID)
	if err != nil {
		u.logger.Warn(u.module, requestID, "[shouldLockAccount]: Failed to retrieve user login attempts: %v", err)
	}

	return len(userLoginAttempts) >= u.maxFailedAuthenticationAttempts
}

func (u *userAuthenticator) lockAccount(ctx context.Context, user *users.User) error {
	user.AccountLocked = true
	return u.repo.UpdateUser(ctx, user)
}
