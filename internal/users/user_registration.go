package users

import (
	"github.com/vigiloauth/vigilo/internal/security"
)

// UserRegistration handles user registration operations.
type UserRegistration struct {
	userStore UserStore
}

// NewUserRegistration creates a new UserRegistration instance.
func NewUserRegistration(userStore UserStore) *UserRegistration {
	return &UserRegistration{userStore: userStore}
}

// Register registers a new user in the system.
// It takes a User object as input, hashes the user's password, and stores the user in the userStore.
// Returns the registered User object and an error if any occurred during the process.
func (r *UserRegistration) Register(user *User) (*User, error) {
	hashedPassword, err := security.HashPassword(user.Password)
	if err != nil {
		return nil, err
	}

	user.Password = hashedPassword
	if err := r.userStore.AddUser(user); err != nil {
		return nil, err
	}

	return user, nil
}
