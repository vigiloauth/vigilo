package auth

import (
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

type Registration interface {
	RegisterUser(user *users.User) (*users.UserRegistrationResponse, error)
}

var _ Registration = (*RegistrationService)(nil)

// RegistrationService handles user registration operations.
type RegistrationService struct {
	userStore    users.UserStore
	jwtConfig    *config.JWTConfig
	tokenManager token.TokenManager
}

// NewRegistrationService creates a new UserRegistration instance.
func NewRegistrationService(userStore users.UserStore, tokenManager token.TokenManager) *RegistrationService {
	return &RegistrationService{
		userStore:    userStore,
		jwtConfig:    config.GetServerConfig().JWTConfig(),
		tokenManager: tokenManager,
	}
}

// RegisterUser registers a new user in the system.
// It takes a User object as input, hashes the user's password, and stores the user in the userStore.
// Returns the registered User object and an error if any occurred during the process.
func (r *RegistrationService) RegisterUser(user *users.User) (*users.UserRegistrationResponse, error) {
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to hash password")
	}

	if existingUser := r.userStore.GetUser(user.Email); existingUser != nil {
		return nil, errors.NewDuplicateUserError("email")
	}

	user.Password = hashedPassword
	if err := r.userStore.AddUser(user); err != nil {
		return nil, errors.Wrap(err, "Failed to create new user")
	}

	jwtToken, err := r.tokenManager.GenerateToken(user.Email, r.jwtConfig.ExpirationTime())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate token")
	}

	return users.NewUserRegistrationResponse(user, jwtToken), nil
}
