package auth

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

type AuthenticationService struct {
	userStore         users.UserStore
	loginAttemptStore *LoginAttemptStore
	config            *config.ServerConfig
	maxFailedAttempts int
	artificialDelay   time.Duration
	tokenService      *token.TokenService
}

func NewAuthenticationService(userStore users.UserStore, loginAttemptStore *LoginAttemptStore, tokenService *token.TokenService) *AuthenticationService {
	return &AuthenticationService{
		userStore:         userStore,
		loginAttemptStore: loginAttemptStore,
		config:            config.GetServerConfig(),
		tokenService:      tokenService,
		maxFailedAttempts: config.GetServerConfig().LoginConfig().MaxFailedAttempts(),
		artificialDelay:   config.GetServerConfig().LoginConfig().Delay(),
	}
}

// AuthenticateUser logs in a user and returns a token if successful. Each failed login attempt will be saved and if the attempts
// exceed the threshold, the account will be locked.
func (l *AuthenticationService) AuthenticateUser(loginUser *users.User, loginAttempt *LoginAttempt) (*users.UserLoginResponse, error) {
	startTime := time.Now()

	retrievedUser, found := l.userStore.GetUser(loginUser.Email)
	if !found {
		l.applyArtificialDelay(startTime)
		return nil, errors.NewInvalidCredentialsError()
	}

	if retrievedUser.AccountLocked {
		l.applyArtificialDelay(startTime)
		return nil, errors.NewAccountLockedError()
	}

	loginAttempt.UserID = retrievedUser.ID
	if passwordsAreEqual := utils.ComparePasswordHash(loginUser.Password, retrievedUser.Password); !passwordsAreEqual {
		l.handleFailedLoginAttempt(&retrievedUser, loginAttempt)
		l.applyArtificialDelay(startTime)
		return nil, errors.NewInvalidCredentialsError()
	}

	jwtToken, err := l.tokenService.GenerateToken(retrievedUser.Email, l.config.JWTConfig().ExpirationTime())
	if err != nil {
		return nil, err
	}

	retrievedUser.LastFailedLogin = time.Time{}
	_ = l.userStore.UpdateUser(&retrievedUser)

	l.applyArtificialDelay(startTime)
	return users.NewUserLoginResponse(&retrievedUser, jwtToken), nil
}

// applyArtificialDelay applies an artificial delay to normalize response times.
func (l *AuthenticationService) applyArtificialDelay(startTime time.Time) {
	time.Sleep(time.Until(startTime.Add(l.artificialDelay)))
}

func (l *AuthenticationService) handleFailedLoginAttempt(retrievedUser *users.User, loginAttempt *LoginAttempt) {
	retrievedUser.LastFailedLogin = time.Now()
	l.loginAttemptStore.SaveLoginAttempt(loginAttempt)
	_ = l.userStore.UpdateUser(retrievedUser)

	loginAttempts := l.loginAttemptStore.GetLoginAttempts(retrievedUser.ID)
	if len(loginAttempts) >= l.maxFailedAttempts {
		retrievedUser.AccountLocked = true
		_ = l.userStore.UpdateUser(retrievedUser)
	}
}
