package auth

import (
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// Registration defines the interface for user registration operations.
type Registration interface {
	RegisterUser(user *users.User) (*users.UserRegistrationResponse, error)
}

// Ensure RegistrationService implements the Registration interface.
var _ Registration = (*RegistrationService)(nil)

// RegistrationService handles user registration operations.
type RegistrationService struct {
	userStore    users.UserStore    // User data store.
	jwtConfig    *config.JWTConfig  // JWT configuration.
	tokenManager token.TokenManager // Token manager for JWT.
}

// NewRegistrationService creates a new RegistrationService instance.
//
// Parameters:
//
//	userStore users.UserStore: The user data store.
//	tokenManager token.TokenManager: The token manager.
//
// Returns:
//
//	*RegistrationService: A new RegistrationService instance.
func NewRegistrationService(userStore users.UserStore, tokenManager token.TokenManager) *RegistrationService {
	return &RegistrationService{
		userStore:    userStore,
		jwtConfig:    config.GetServerConfig().JWTConfig(),
		tokenManager: tokenManager,
	}
}

// RegisterUser registers a new user in the system.
// It takes a User object as input, hashes the user's password, and stores the user in the userStore.
//
// Parameters:
//
//	user *users.User: The user to register.
//
// Returns:
//
//	*users.UserRegistrationResponse: The registered user object and JWT token.
//	error: An error if any occurred during the process.
func (r *RegistrationService) RegisterUser(user *users.User) (*users.UserRegistrationResponse, error) {
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to encrypt password")
	}

	if existingUser := r.userStore.GetUser(user.Email); existingUser != nil {
		return nil, errors.New(errors.ErrCodeDuplicateUser, "user already exists with the provided email")
	}

	user.Password = hashedPassword
	if err := r.userStore.AddUser(user); err != nil {
		return nil, errors.Wrap(err, "", "failed to create new user")
	}

	jwtToken, err := r.tokenManager.GenerateToken(user.Email, r.jwtConfig.ExpirationTime())
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to generate session token")
	}

	return users.NewUserRegistrationResponse(user, jwtToken), nil
}
