package users

import (
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/security"
)

// UserRegistration handles user registration operations.
type UserRegistration struct {
	userStore UserStore
	jwtConfig *config.JWTConfig
}

// NewUserRegistration creates a new UserRegistration instance.
func NewUserRegistration(userStore UserStore, jwtConfig *config.JWTConfig) *UserRegistration {
	return &UserRegistration{
		userStore: userStore,
		jwtConfig: jwtConfig,
	}
}

// Register registers a new user in the system.
// It takes a User object as input, hashes the user's password, and stores the user in the userStore.
// Returns the registered User object and an error if any occurred during the process.
func (r *UserRegistration) Register(user *User) (*UserRegistrationResponse, error) {
	hashedPassword, err := security.HashPassword(user.Password)
	if err != nil {
		return nil, err
	}

	user.Password = hashedPassword
	if err := r.userStore.AddUser(user); err != nil {
		return nil, err
	}

	token, err := security.GenerateJWT(user.Email, *r.jwtConfig)
	if err != nil {
		return nil, err
	}

	return NewUserRegistrationResponse(user, token), nil
}
