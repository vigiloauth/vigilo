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

const (
	tokenDuration    time.Duration = 15 * time.Minute
	resetResponseMsg string        = "Password reset instructions have been sent to your email if an account exists."
)

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
		return &users.UserPasswordResetResponse{Message: resetResponseMsg}, nil
	}

	resetToken, err := p.tokenManager.GenerateToken(userEmail, tokenDuration)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to generate reset token")
	}

	resetURL, err := p.constructResetURL(resetToken)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to construct reset URL")
	}

	if err := p.generateAndSendEmail(userEmail, resetURL, resetToken); err != nil {
		return nil, errors.Wrap(err, "Failed to send email")
	}

	p.addTokenToStore(resetToken, userEmail)
	return &users.UserPasswordResetResponse{Message: resetResponseMsg}, nil
}

func (p *PasswordResetService) constructResetURL(resetToken string) (string, error) {
	resetURLBase := config.GetServerConfig().BaseURL()
	if resetURLBase == "" {
		return "", errors.NewEmptyInputError("Base URL")
	}

	return fmt.Sprintf("%s?token=%s", resetURLBase, resetToken), nil
}

func (p *PasswordResetService) generateAndSendEmail(userEmail, resetURL, resetToken string) error {
	emailRequest := email.NewPasswordResetRequest(userEmail, resetURL, resetToken, time.Now().Add(tokenDuration))
	emailRequest = *p.emailService.GenerateEmail(emailRequest)
	if err := p.emailService.SendEmail(emailRequest); err != nil {
		return err
	}

	return nil
}

func (p *PasswordResetService) addTokenToStore(resetToken, userEmail string) {
	tokenExpirationTime := time.Now().Add(tokenDuration)
	p.tokenManager.AddToken(resetToken, userEmail, tokenExpirationTime)
}
