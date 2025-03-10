package auth

import (
	"fmt"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/email"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
)

const tokenDuration time.Duration = 15 * time.Minute

type PasswordReset interface {
	SendPasswordResetEmail(userEmail string) (*users.UserPasswordResetResponse, error)
}

var _ PasswordReset = (*PasswordResetService)(nil)

type PasswordResetService struct {
	tokenManager token.TokenManager
	userStore    users.UserStore
	emailService email.EmailService
}

func NewPasswordResetService(tokenManager token.TokenManager, userStore users.UserStore, emailService email.EmailService) *PasswordResetService {
	return &PasswordResetService{
		tokenManager: tokenManager,
		userStore:    userStore,
		emailService: emailService,
	}
}

func (p *PasswordResetService) SendPasswordResetEmail(userEmail string) (*users.UserPasswordResetResponse, error) {
	if user := p.userStore.GetUser(userEmail); user == nil {
		return &users.UserPasswordResetResponse{
			Message: "If an account with the given email exists, a password reset link has been sent.",
		}, nil
	}

	resetToken, err := p.tokenManager.GenerateToken(userEmail, tokenDuration)
	if err != nil {
		return nil, err
	}

	tokenExpirationTime := time.Now().Add(tokenDuration)
	p.tokenManager.AddToken(resetToken, userEmail, tokenExpirationTime)

	resetURL, err := p.constructResetURL(resetToken)
	if err != nil {
		return nil, err
	}

	emailRequest := email.NewPasswordResetRequest(userEmail, resetURL, resetToken, tokenExpirationTime)
	emailRequest = *p.emailService.GenerateEmail(emailRequest)
	if err := p.emailService.SendEmail(emailRequest); err != nil {
		return nil, err
	}

	return &users.UserPasswordResetResponse{
		Message: "If an account with the given email exists, a password reset link has been sent.",
	}, nil
}

func (p *PasswordResetService) constructResetURL(resetToken string) (string, error) {
	resetURLBase := config.GetServerConfig().BaseURL()
	if resetURLBase == "" {
		return "", errors.NewEmptyInputError("Base URL")
	}

	return fmt.Sprintf("%s?token=%s", resetURLBase, resetToken), nil
}
