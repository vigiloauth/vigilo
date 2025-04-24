package service

import (
	"context"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/internal/crypto"
	audit "github.com/vigiloauth/vigilo/internal/domain/audit"
	email "github.com/vigiloauth/vigilo/internal/domain/email"
	login "github.com/vigiloauth/vigilo/internal/domain/login"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
)

var _ users.UserService = (*userService)(nil)

type userService struct {
	userRepo     users.UserRepository
	tokenService token.TokenService
	loginService login.LoginAttemptService
	emailService email.EmailService
	auditLogger  audit.AuditLogger

	tokenConfig     *config.TokenConfig
	artificialDelay time.Duration
	logger          *config.Logger
	module          string
}

func NewUserService(
	userRepo users.UserRepository,
	tokenService token.TokenService,
	loginAttemptRepository login.LoginAttemptService,
	emailService email.EmailService,
	auditLogger audit.AuditLogger,
) users.UserService {
	return &userService{
		userRepo:        userRepo,
		tokenService:    tokenService,
		loginService:    loginAttemptRepository,
		emailService:    emailService,
		auditLogger:     auditLogger,
		tokenConfig:     config.GetServerConfig().TokenConfig(),
		artificialDelay: config.GetServerConfig().LoginConfig().Delay(),
		logger:          config.GetServerConfig().Logger(),
		module:          "User Service",
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
func (u *userService) CreateUser(ctx context.Context, user *users.User) (*users.UserRegistrationResponse, error) {
	requestID := utils.GetRequestID(ctx)

	if err := u.saveUser(ctx, user); err != nil {
		u.auditLogger.StoreEvent(ctx, audit.RegistrationAttempt, false, audit.RegistrationAction, audit.EmailMethod, err)
		u.logger.Error(u.module, requestID, "[CreateUser]: Failed to save user: %v", err)
		return nil, err
	}

	if err := u.sendVerificationEmail(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, "[CreateUser]: Failed to send account verification email: %v", err)
		return nil, nil
	}

	accessToken, err := u.tokenService.GenerateToken(
		ctx,
		user.Email,
		strings.Join(user.Scopes, " "),
		strings.Join(user.Roles, " "),
		u.tokenConfig.ExpirationTime(),
	)

	if err != nil {
		u.logger.Error(u.module, requestID, "[CreateUser]: Failed to generate a session token: %v", err)
		return nil, errors.Wrap(err, "", "failed to generate session token")
	}

	u.auditLogger.StoreEvent(ctx, audit.RegistrationAttempt, true, audit.RegistrationAction, audit.EmailMethod, nil)
	return users.NewUserRegistrationResponse(user, accessToken), nil
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
func (u *userService) GetUserByUsername(ctx context.Context, username string) (*users.User, error) {
	requestID := utils.GetRequestID(ctx)
	u.logger.Debug(u.module, requestID, "[GetUserByUsername]: Retrieving user by username=[%s]", username)
	return u.userRepo.GetUserByUsername(ctx, username)
}

// HandleOAuthLogin authenticates a user based on an OAuth login request.
//
// This method constructs a User object and a UserLoginAttempt object from the provided
// login request and request metadata, then delegates the authentication process
// to the AuthenticateUser method.
//
// Parameters:
//   - ctx Context: The context for managing timeouts, cancellations, and for retrieving/storing request metadata.
//   - request *UserLoginRequest: The login request containing the user's email and password.
//   - clientID string: The client ID of the OAuth client making the request.
//   - redirectURI string: The redirect URI to use if authentication is successful.
//
// Returns:
//   - *UserLoginResponse: The response containing user information and a JWT token if authentication is successful.
//   - error: An error if authentication fails or if the input is invalid.
func (u *userService) HandleOAuthLogin(ctx context.Context, request *users.UserLoginRequest, clientID, redirectURI string) (*users.UserLoginResponse, error) {
	requestID := utils.GetRequestID(ctx)
	if err := request.Validate(); err != nil {
		u.logger.Error(u.module, requestID, "[HandleOAuthLogin]: Failed to validate request: %v", err)
		return nil, err
	}

	response, err := u.AuthenticateUserWithRequest(ctx, request)
	if err != nil {
		u.logger.Error(u.module, requestID, "[HandleOAuthLogin]: Failed to authenticate user: %v", err)
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
//   - ctx Context: The context for managing timeouts, cancellations, and for retrieving/storing request metadata.
//   - request *UserLoginRequest: The login request containing the user's email and password.
//
// Returns:
//   - *UserLoginResponse: The response containing user information and a JWT token if authentication is successful.
//   - error: An error if authentication fails or if the input is invalid.
func (u *userService) AuthenticateUserWithRequest(ctx context.Context, request *users.UserLoginRequest) (*users.UserLoginResponse, error) {
	requestID := utils.GetRequestID(ctx)
	user := &users.User{
		ID:       request.ID,
		Username: request.Username,
		Password: request.Password,
	}

	loginAttempt := &users.UserLoginAttempt{
		Timestamp:      time.Now().UTC(),
		FailedAttempts: 0,
	}

	if IP := utils.GetValueFromContext(ctx, constants.ContextKeyIPAddress); IP != nil {
		loginAttempt.IPAddress, _ = IP.(string)
	} else {
		u.logger.Error(u.module, requestID, "[AuthenticateUserWithRequest]: There was an error retrieving the IP address from context")
		return nil, errors.NewInternalServerError()
	}

	if userAgent := utils.GetValueFromContext(ctx, constants.ContextKeyUserAgent); userAgent != nil {
		loginAttempt.UserAgent, _ = userAgent.(string)
	} else {
		u.logger.Error(u.module, requestID, "[AuthenticateUserWithRequest]: There was an error retrieving the user agent from context")
		return nil, errors.NewInternalServerError()
	}

	return u.authenticateUser(ctx, user, loginAttempt)
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
func (u *userService) GetUserByID(ctx context.Context, userID string) (*users.User, error) {
	requestID := utils.GetRequestID(ctx)
	u.logger.Debug(u.module, requestID, "[GetUserByID]: Retrieving user by ID=[%s]", utils.TruncateSensitive(userID))
	return u.userRepo.GetUserByID(ctx, userID)
}

// ValidateVerificationCode validates the verification code and updates the user
// if verification was successful.
//
// Parameter:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - verificationCode string: The verification code to verify.
//
// Returns:
//   - error: an error if validation fails, otherwise nil.
func (u *userService) ValidateVerificationCode(ctx context.Context, verificationCode string) error {
	requestID := utils.GetRequestID(ctx)
	if verificationCode == "" {
		u.logger.Error(u.module, requestID, "[ValidateVerificationCode]: Verification code provided is empty")
		return errors.New(errors.ErrCodeInvalidRequest, "missing one or more required parameters in the request")
	}

	if err := u.tokenService.ValidateToken(ctx, verificationCode); err != nil {
		u.logger.Error(u.module, requestID, "[ValidateVerificationCode]: Failed to validate verification code: %v", err)
		return errors.New(errors.ErrCodeUnauthorized, "the verification code is either expired or does not exist")
	}

	claims, err := u.tokenService.ParseToken(verificationCode)
	if err != nil {
		u.logger.Error(u.module, requestID, "[ValidateVerificationCode]: Failed to parse verification code: %v", err)
		return errors.NewInternalServerError()
	}

	user, err := u.userRepo.GetUserByEmail(ctx, claims.Subject)
	if err != nil {
		u.logger.Error(u.module, requestID, "[ValidateVerificationCode]: An error occurred retrieving the user by username: %v", err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred retrieving the user")
	}

	if user == nil {
		return errors.New(errors.ErrCodeUnauthorized, "the verification code is invalid")
	}

	if user.Verified {
		return nil
	}

	user.Verified = true
	if err := u.updateAuthenticatedUser(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, "[ValidateVerificationCode]: Failed to update the authenticated user: %v", err)
		return err
	}

	return nil
}

// DeleteUnverifiedUsers deletes any user that hasn't verified their account and
// has been created for over a week.
//
// Parameter:
//   - ctx Context: The context for managing timeouts and cancellations.
//
// Returns:
//   - error: an error if deletion fails, otherwise nil.
func (u *userService) DeleteUnverifiedUsers(ctx context.Context) error {
	expiredUsers, err := u.userRepo.FindUnverifiedUsersOlderThanWeek(ctx)
	if err != nil {
		u.logger.Error(u.module, "", "[DeleteUnverifiedUsers]: An error occurred retrieving unverified users: %v", err)
		return errors.NewInternalServerError()
	}

	for _, user := range expiredUsers {
		if err := u.userRepo.DeleteUserByID(ctx, user.ID); err != nil {
			u.logger.Error(u.module, "", "[DeleteUnverifiedUsers]: An error occurred deleting user by ID=[%s]: %v", utils.TruncateSensitive(user.ID), err)
			u.auditLogger.StoreEvent(ctx, audit.AccountDeletion, false, audit.AccountDeletionAction, audit.IDMethod, err)
			return errors.NewInternalServerError()
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
func (u *userService) ResetPassword(ctx context.Context, userEmail, newPassword, resetToken string) (*users.UserPasswordResetResponse, error) {
	requestID := utils.GetRequestID(ctx)
	storedToken, err := u.tokenService.ParseToken(resetToken)
	if err != nil {
		u.logger.Error(u.module, requestID, "[ResetPassword]: Failed to parse reset token: %v", err)
		return nil, errors.Wrap(err, "", "failed to parse reset token")
	}

	if storedToken.Subject != userEmail {
		err := errors.New(errors.ErrCodeUnauthorized, "invalid reset token")
		u.logger.Error(u.module, requestID, "[ResetPassword]: Invalid reset token. Subject does not match user email=[%s]: %v", userEmail, err)
		u.logPasswordResetEvent(ctx, false, err, "")
		return nil, err
	}

	encryptedPassword, err := crypto.HashString(newPassword)
	if err != nil {
		u.logger.Error(u.module, requestID, "[ResetPassword]: Failed to encrypt password: %v", err)
		u.logPasswordResetEvent(ctx, false, errors.NewInternalServerError(), "")
		return nil, errors.NewInternalServerError()
	}

	user, err := u.userRepo.GetUserByEmail(ctx, userEmail)
	if err != nil {
		u.logger.Error(u.module, requestID, "[ResetPassword]: An error occurred retrieving the user: %v", err)
		wrappedErr := errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred retrieving the user")
		u.logPasswordResetEvent(ctx, false, wrappedErr, "")
		return nil, wrappedErr
	}

	if user == nil {
		err := errors.New(errors.ErrCodeUserNotFound, "user not found with the provided email address")
		u.logPasswordResetEvent(ctx, false, err, "")
		u.logger.Error(u.module, requestID, "[ResetPassword]: Failed to retrieve user by email. User does not exist.")
		return nil, err
	}

	if user.AccountLocked {
		u.logger.Debug(u.module, requestID, "[ResetPassword]: Unlocking account for user=[%s]", (userEmail))
		user.AccountLocked = false
	}

	user.Password = encryptedPassword
	if err := u.userRepo.UpdateUser(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, "[ResetPassword]: Failed to update user: %v", err)
		wrappedErr := errors.Wrap(err, "", "failed to update user")
		u.logPasswordResetEvent(ctx, false, wrappedErr, user.ID)
		return nil, wrappedErr
	}

	if err := u.tokenService.DeleteToken(ctx, resetToken); err != nil {
		u.logger.Error(u.module, requestID, "[ResetPassword]: failed to delete reset token: %v", err)
		return nil, errors.Wrap(err, "", "failed to delete reset token")
	}

	u.logPasswordResetEvent(ctx, true, nil, user.ID)
	return &users.UserPasswordResetResponse{
		Message: "Password has been reset successfully",
	}, nil
}

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
//   - loginUser *users.User: The user attempting to log in.
//   - loginAttempt *users.LoginAttempt: The login attempt information.
//
// Returns:
//   - *users.UserLoginResponse: The user login response containing user information and JWT token.
//   - error: An error if authentication fails.
func (u *userService) authenticateUser(ctx context.Context, loginUser *users.User, loginAttempt *users.UserLoginAttempt) (*users.UserLoginResponse, error) {
	startTime := time.Now()
	defer u.applyArtificialDelay(startTime)
	requestID := utils.GetRequestID(ctx)

	retrievedUser, err := u.userRepo.GetUserByID(ctx, loginUser.ID)
	if err != nil {
		u.logger.Error(u.module, requestID, "An error occurred retrieving the user by ID: %v", err)
		u.logLoginEvent(ctx, false, err, loginAttempt.UserID)
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred retrieving the user")
	} else if retrievedUser == nil {
		err := errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
		u.logLoginEvent(ctx, false, err, loginAttempt.UserID)
		u.logger.Error(u.module, requestID, "Failed to retrieve user by ID=[%s]: %v", utils.TruncateSensitive(loginUser.ID), err)
		return nil, err
	}

	if retrievedUser.AccountLocked {
		err := errors.New(errors.ErrCodeAccountLocked, "account is locked due to too many failed login attempts -- please reset your password")
		u.logLoginEvent(ctx, false, err, retrievedUser.ID)
		u.logger.Error(u.module, requestID, "Failed to authenticate due to too many failed attempts=[%d], timestamp=[%s]", loginAttempt.FailedAttempts, loginAttempt.Timestamp)
		return nil, err
	}

	if err := u.comparePasswords(ctx, loginUser, retrievedUser, loginAttempt); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authenticate user")
		u.logLoginEvent(ctx, false, err, retrievedUser.ID)
		return nil, wrappedErr
	}

	accessToken, err := u.tokenService.GenerateToken(
		ctx,
		retrievedUser.ID,
		strings.Join(retrievedUser.Scopes, " "),
		strings.Join(retrievedUser.Roles, " "),
		u.tokenConfig.ExpirationTime(),
	)

	if err != nil {
		u.logger.Error(u.module, requestID, "Failed to generate access token for user=[%s]: %v", utils.TruncateSensitive(retrievedUser.ID), err)
		return nil, errors.NewInternalServerError()
	}

	retrievedUser.LastFailedLogin = time.Time{}
	if err := u.updateAuthenticatedUser(ctx, retrievedUser); err != nil {
		u.logger.Error(u.module, requestID, "Failed to update authenticated user: %v", err)
		u.logLoginEvent(ctx, false, err, retrievedUser.ID)
		return nil, err
	}

	u.logLoginEvent(ctx, true, nil, retrievedUser.ID)
	return users.NewUserLoginResponse(retrievedUser, accessToken), nil
}

func (u *userService) updateAuthenticatedUser(ctx context.Context, user *users.User) error {
	requestID := utils.GetRequestID(ctx)
	if err := u.userRepo.UpdateUser(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, ": Failed to update user after successful authentication: %v", err)
		return errors.Wrap(err, "", "failed to update user")
	}

	return nil
}

func (u *userService) comparePasswords(ctx context.Context, loginUser *users.User, existingUser *users.User, loginAttempt *users.UserLoginAttempt) error {
	requestID := utils.GetRequestID(ctx)
	loginAttempt.UserID = existingUser.ID
	if passwordsAreEqual := crypto.CompareHash(loginUser.Password, existingUser.Password); !passwordsAreEqual {
		u.logger.Error(u.module, requestID, "Failed to compare passwords. Passwords do not match")
		if err := u.loginService.HandleFailedLoginAttempt(ctx, existingUser, loginAttempt); err != nil {
			return errors.NewInternalServerError()
		}

		err := errors.New(errors.ErrCodeInvalidCredentials, "invalid credentials")
		u.logger.Error(u.module, requestID, "Failed to authenticate user=[%s]: %v", utils.TruncateSensitive(loginUser.ID), err)
		return err
	}

	return nil
}

func (u *userService) userExistsByEmail(ctx context.Context, email string) (bool, error) {
	requestID := utils.GetRequestID(ctx)
	user, err := u.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		u.logger.Error(u.module, requestID, "Failed to retrieve user by email=[%s]: %v", email, err)
		return false, err
	}

	return user != nil, nil
}

func (u *userService) encryptPassword(user *users.User) error {
	hashedPassword, err := crypto.HashString(user.Password)
	if err != nil {
		u.logger.Error(u.module, "", "Failed to encrypt password: %v", err)
		return errors.Wrap(err, "", "failed to encrypt password")
	}

	user.Password = hashedPassword
	return nil
}

func (u *userService) saveUser(ctx context.Context, user *users.User) error {
	requestID := utils.GetRequestID(ctx)
	exists, err := u.userExistsByEmail(ctx, user.Email)
	if err != nil {
		u.logger.Error(u.module, requestID, "[CreateUser]: An error occurred retrieving the user: %v", err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred retrieving the user")
	} else if exists {
		return errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided email")
	}
	if err := u.encryptPassword(user); err != nil {
		u.logger.Error(u.module, requestID, "Failed to create new user: %v", err)
		return errors.NewInternalServerError()
	}

	user.CreatedAt = time.Now()
	if user.HasRole(constants.AdminRole) {
		user.ID = constants.AdminRoleIDPrefix + crypto.GenerateUUID()
	} else {
		user.ID = constants.UserRoleIDPrefix + crypto.GenerateUUID()
	}

	if err := u.userRepo.AddUser(ctx, user); err != nil {
		u.logger.Error(u.module, requestID, "Failed to save user: %v", err)
		return errors.NewInternalServerError()
	}

	return nil
}

func (u *userService) sendVerificationEmail(ctx context.Context, user *users.User) error {
	requestID := utils.GetRequestID(ctx)

	verificationCode, err := u.tokenService.GenerateToken(
		ctx,
		user.Email,
		strings.Join(user.Scopes, " "),
		strings.Join(user.Roles, " "),
		u.tokenConfig.AccessTokenDuration(),
	)

	if err != nil {
		u.logger.Error(u.module, requestID, "Failed to generate verification code: %v", err)
		return err
	}

	emailRequest := email.NewEmailRequest(user.Email, verificationCode, verificationCode, email.AccountVerification)
	return u.emailService.SendEmail(ctx, emailRequest)
}

func (u *userService) logLoginEvent(ctx context.Context, success bool, err error, userID string) {
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserID, userID)
	u.auditLogger.StoreEvent(ctx, audit.LoginAttempt, success, audit.AuthenticationAction, audit.OAuthMethod, err)
}

func (u *userService) logPasswordResetEvent(ctx context.Context, success bool, err error, userID string) {
	ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserID, userID)
	u.auditLogger.StoreEvent(ctx, audit.PasswordChange, success, audit.PasswordResetAction, audit.EmailMethod, err)
}
