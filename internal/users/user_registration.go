package users

import (
	"regexp"
)

type UserRegistration struct{}

func NewUserRegistration() *UserRegistration {
	return &UserRegistration{}
}

func (r *UserRegistration) RegisterUser(user *User) (*User, error) {
	if !isValidEmailFormat(user.Email) {
		return nil, &EmailFormatError{Email: user.Email}
	}

	if len(user.Password) < 8 {
		return nil, &PasswordLengthError{Length: len(user.Password)}
	}

	if err := GetUserCache().AddUser(*user); err != nil {
		return nil, err
	}

	return user, nil
}

func isValidEmailFormat(email string) bool {
	pattern := regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	return pattern.MatchString(email)
}