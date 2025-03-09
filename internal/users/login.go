package users

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/auth"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/security"
	"github.com/vigiloauth/vigilo/internal/token"
)

// UserLogin handles user login operations.
type UserLogin struct {
	userStore         UserStore
	loginAttemptStore *auth.LoginAttemptStore
	config            *config.ServerConfig
	maxFailedAttempts int
	artificialDelay   time.Duration
	tokenService      *token.TokenService
}

func NewUserLogin(userStore UserStore, loginAttemptStore *auth.LoginAttemptStore, config *config.ServerConfig, tokenService *token.TokenService) *UserLogin {
	return &UserLogin{
		userStore:         userStore,
		loginAttemptStore: loginAttemptStore,
		config:            config,
		tokenService:      tokenService,
		maxFailedAttempts: config.LoginConfig().MaxFailedAttempts(),
		artificialDelay:   config.LoginConfig().Delay(),
	}
}

// Login logs in a user and returns a token if successful. Each failed login attempt will be saved and if the attempts
// exceed the threshold, the account will be locked.
func (l *UserLogin) Login(loginUser *User, loginAttempt *auth.LoginAttempt) (*UserLoginResponse, error) {
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
	if passwordsAreEqual := security.ComparePasswordHash(loginUser.Password, retrievedUser.Password); !passwordsAreEqual {
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
	return NewUserLoginResponse(&retrievedUser, jwtToken), nil
}

// applyArtificialDelay applies an artificial delay to normalize response times.
func (l *UserLogin) applyArtificialDelay(startTime time.Time) {
	time.Sleep(time.Until(startTime.Add(l.artificialDelay)))
}

func (l *UserLogin) handleFailedLoginAttempt(retrievedUser *User, loginAttempt *auth.LoginAttempt) {
	retrievedUser.LastFailedLogin = time.Now()
	l.loginAttemptStore.SaveLoginAttempt(loginAttempt)
	_ = l.userStore.UpdateUser(retrievedUser)

	loginAttempts := l.loginAttemptStore.GetLoginAttempts(retrievedUser.ID)
	if len(loginAttempts) >= l.maxFailedAttempts {
		retrievedUser.AccountLocked = true
		_ = l.userStore.UpdateUser(retrievedUser)
	}
}
