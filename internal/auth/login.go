package auth

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/security"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
)

// UserLogin handles user login operations.
type UserLogin struct {
	userStore         users.UserStore
	loginAttemptStore *LoginAttemptStore
	config            *config.ServerConfig
	maxFailedAttempts int
	artificialDelay   time.Duration
}

func NewUserLogin(userStore users.UserStore, loginAttemptStore *LoginAttemptStore, config *config.ServerConfig) *UserLogin {
	return &UserLogin{
		userStore:         userStore,
		loginAttemptStore: loginAttemptStore,
		config:            config,
		maxFailedAttempts: config.LoginConfig().MaxFailedAttempts(),
		artificialDelay:   config.LoginConfig().Delay(),
	}
}

// Login logs in a user and returns a token if successful. Each failed login attempt will be saved and if the attempts
// exceed the threshold, the account will be locked.
func (l *UserLogin) Login(loginUser *users.User, loginAttempt *LoginAttempt) (*users.UserLoginResponse, error) {
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

	jwtToken, err := token.GenerateJWT(retrievedUser.Email, *l.config.JWTConfig())
	if err != nil {
		return nil, err
	}

	retrievedUser.LastFailedLogin = time.Time{}
	_ = l.userStore.UpdateUser(&retrievedUser)

	l.applyArtificialDelay(startTime)
	return users.NewUserLoginResponse(&retrievedUser, jwtToken), nil
}

// applyArtificialDelay applies an artificial delay to normalize response times.
func (l *UserLogin) applyArtificialDelay(startTime time.Time) {
	time.Sleep(time.Until(startTime.Add(l.artificialDelay)))
}

func (l *UserLogin) handleFailedLoginAttempt(retrievedUser *users.User, loginAttempt *LoginAttempt) {
	retrievedUser.LastFailedLogin = time.Now()
	l.loginAttemptStore.SaveLoginAttempt(loginAttempt)
	_ = l.userStore.UpdateUser(retrievedUser)

	loginAttempts := l.loginAttemptStore.GetLoginAttempts(retrievedUser.ID)
	if len(loginAttempts) >= l.maxFailedAttempts {
		retrievedUser.AccountLocked = true
		_ = l.userStore.UpdateUser(retrievedUser)
	}
}
