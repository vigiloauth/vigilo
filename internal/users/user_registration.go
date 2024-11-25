package users

import (
	"regexp"
)

const defaultPasswordLength = 8

type UserRegistration struct{}

func NewUserRegistration() *UserRegistration {
	return &UserRegistration{}
}

func (r *UserRegistration) RegisterUser(user *User) (*User, error) {
	if !isValidEmailFormat(user.Email) {
		return nil, &EmailFormatError{Email: user.Email}
	}

	if len(user.Password) < defaultPasswordLength {
		return nil, &PasswordLengthError{Length: len(user.Password)}
	}

	if err := GetInMemoryUserStore().AddUser(*user); err != nil {
		return nil, err
	}

	return user, nil
}

func isValidEmailFormat(email string) bool {
	pattern := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return pattern.MatchString(email)
}
