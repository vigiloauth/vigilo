package users

import (
	"github.com/vigiloauth/vigilo/internal/errors"
	"golang.org/x/crypto/bcrypt"
)

// UserLogin handles user login operations.
type UserLogin struct {
	userStore UserStore
}

func NewUserLogin(userStore UserStore) *UserLogin {
	return &UserLogin{userStore: userStore}
}

// LoginUser logs in a user and returns a token if successful
func (l *UserLogin) LoginUser(user *User) (*User, error) {
	if err := isValidEmailFormat(user.Email); err {
		return nil, errors.NewEmailFormatError(UserFieldConstants.Email)
	}

	retrievedUser, found := l.userStore.GetUser(user.Email)
	if !found {
		return nil, errors.NewUserNotFoundError()
	}

	if err := bcrypt.CompareHashAndPassword([]byte(retrievedUser.Password), []byte(user.Password)); err != nil {
		return nil, errors.NewInvalidCredentialsError()
	}

	return &retrievedUser, nil
}
