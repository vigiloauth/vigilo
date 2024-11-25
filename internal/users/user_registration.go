package users

import (
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/security"
	"regexp"
)

type UserRegistration struct{}

func NewUserRegistration() *UserRegistration {
	return &UserRegistration{}
}

func (r *UserRegistration) RegisterUser(user *User) (*User, error) {
	if !isValidEmailFormat(user.Email) {
		return nil, errors.NewEmailFormatError(user.Email)
	}

	user.Password = security.HashPassword(user.Password)
	if err := GetUserCache().AddUser(*user); err != nil {
		return nil, err
	}

	return user, nil
}

func isValidEmailFormat(email string) bool {
	pattern := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return pattern.MatchString(email)
}
