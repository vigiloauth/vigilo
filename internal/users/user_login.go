package users

import (
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/security"
)

// UserLogin handles user login operations.
type UserLogin struct {
	userStore UserStore
}

func NewUserLogin(userStore UserStore) *UserLogin {
	return &UserLogin{userStore: userStore}
}

// Login logs in a user and returns a token if successful
func (l *UserLogin) Login(user *User) (*User, error) {
	if !isValidEmailFormat(user.Email) {
		return nil, errors.NewEmailFormatError(UserFieldConstants.Email)
	}

	retrievedUser, found := l.userStore.GetUser(user.Email)
	if !found {
		return nil, errors.NewUserNotFoundError()
	}

	if !security.ComparePasswordHash(user.Password, retrievedUser.Password) {
		return nil, errors.NewInvalidCredentialsError()
	}

	return &retrievedUser, nil
}
