package users

import (
	"github.com/vigiloauth/vigilo/internal/security"
)

type UserRegistration struct {
	userStore UserStore
}

func NewUserRegistration(userStore UserStore) *UserRegistration {
	return &UserRegistration{userStore: userStore}
}

func (r *UserRegistration) RegisterUser(user *User) (*User, error) {
	user.Password = security.HashPassword(user.Password)
	if err := r.userStore.AddUser(*user); err != nil {
		return nil, err
	}

	return user, nil
}
