package users

import (
	"github.com/vigiloauth/vigilo/internal/security"
)

type UserRegistration struct{}

func NewUserRegistration() *UserRegistration {
	return &UserRegistration{}
}

func (r *UserRegistration) RegisterUser(user *User) (*User, error) {
	user.Password = security.HashPassword(user.Password)
	if err := GetInMemoryUserStore().AddUser(*user); err != nil {
		return nil, err
	}

	return user, nil
}
