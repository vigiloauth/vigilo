package auth

import (
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// RegistrationService handles user registration operations.
type RegistrationService struct {
	userStore    users.UserStore
	jwtConfig    *config.JWTConfig
	tokenService *token.TokenService
}

// NewRegistrationService creates a new UserRegistration instance.
func NewRegistrationService(userStore users.UserStore, tokenService *token.TokenService) *RegistrationService {
	return &RegistrationService{
		userStore:    userStore,
		jwtConfig:    config.GetServerConfig().JWTConfig(),
		tokenService: tokenService,
	}
}

// RegisterUser registers a new user in the system.
// It takes a User object as input, hashes the user's password, and stores the user in the userStore.
// Returns the registered User object and an error if any occurred during the process.
func (r *RegistrationService) RegisterUser(user *users.User) (*users.UserRegistrationResponse, error) {
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		return nil, err
	}

	user.Password = hashedPassword
	if err := r.userStore.AddUser(user); err != nil {
		return nil, err
	}

	jwtToken, err := r.tokenService.GenerateToken(user.Email, r.jwtConfig.ExpirationTime())
	if err != nil {
		return nil, err
	}

	return users.NewUserRegistrationResponse(user, jwtToken), nil
}
