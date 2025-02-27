package auth

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/security"
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
		maxFailedAttempts: config.LoginConfig.MaxFailedAttempts,
		artificialDelay:   config.LoginConfig.Delay,
	}
}

// Login logs in a user and returns a token if successful
func (l *UserLogin) Login(loginUser *users.User, loginAttempt *LoginAttempt) (*users.UserLoginResponse, error) {
	startTime := time.Now()

	retrievedUser, found := l.userStore.GetUser(loginUser.Email)
	if !found {
		l.applyArtificialDelay(startTime)
		return nil, errors.NewInvalidCredentialsError()
	}

	loginAttempt.UserID = retrievedUser.ID
	if !security.ComparePasswordHash(loginUser.Password, retrievedUser.Password) {
		retrievedUser.LastFailedLogin = time.Now()
		l.loginAttemptStore.LogLoginAttempt(loginAttempt)
		_ = l.userStore.UpdateUser(&retrievedUser)

		l.applyArtificialDelay(startTime)
		return nil, errors.NewInvalidCredentialsError()
	}

	token, err := security.GenerateJWT(retrievedUser.Email, *l.config.JWTConfig)
	if err != nil {
		return nil, err
	}

	retrievedUser.LastFailedLogin = time.Time{}
	_ = l.userStore.UpdateUser(&retrievedUser)

	l.applyArtificialDelay(startTime)
	return users.NewUserLoginResponse(&retrievedUser, token), nil
}

// applyArtificialDelay applies an artificial delay to normalize response times.
func (l *UserLogin) applyArtificialDelay(startTime time.Time) {
	time.Sleep(time.Until(startTime.Add(l.artificialDelay)))
}
