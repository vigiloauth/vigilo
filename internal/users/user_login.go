package users

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/security"
)

// UserLogin handles user login operations.
type UserLogin struct {
	userStore         UserStore
	loginAttemptStore *LoginAttemptStore
	config            *config.ServerConfig
	maxFailedAttempts int
}

func NewUserLogin(userStore UserStore, loginAttemptStore *LoginAttemptStore, config *config.ServerConfig) *UserLogin {
	return &UserLogin{
		userStore:         userStore,
		loginAttemptStore: loginAttemptStore,
		config:            config,
		maxFailedAttempts: 5,
	}
}

// Login logs in a user and returns a token if successful
func (l *UserLogin) Login(loginUser *User, loginAttempt *LoginAttempt) (*UserLoginResponse, error) {
	if !isValidEmailFormat(loginUser.Email) {
		return nil, errors.NewInvalidCredentialsError()
	}

	retrievedUser, found := l.userStore.GetUser(loginUser.Email)
	if !found {
		return nil, errors.NewUserNotFoundError()
	}

	loginAttempt.UserID = retrievedUser.ID
	if !security.ComparePasswordHash(loginUser.Password, retrievedUser.Password) {
		retrievedUser.LastFailedLogin = time.Now()
		l.loginAttemptStore.LogLoginAttempt(loginAttempt)
		_ = l.userStore.UpdateUser(&retrievedUser)

		return nil, errors.NewInvalidCredentialsError()
	}

	token, err := security.GenerateJWT(retrievedUser.Email, *l.config.JWTConfig)
	if err != nil {
		return nil, err
	}

	retrievedUser.LastFailedLogin = time.Time{}
	_ = l.userStore.UpdateUser(&retrievedUser)

	return NewUserLoginResponse(&retrievedUser, token), nil
}
