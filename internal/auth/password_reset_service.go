package auth

import (
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/email"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
)

type PasswordResetService struct {
	tokenService *token.TokenService
	userStore    users.UserStore
	emailService email.EmailService
}

func NewPasswordResetService(tokenService *token.TokenService, userStore users.UserStore, emailService email.EmailService) *PasswordResetService {
	return &PasswordResetService{
		tokenService: tokenService,
		userStore:    userStore,
		emailService: emailService,
	}
}

func (p *PasswordResetService) SendPasswordResetEmail(userEmail string) (*users.UserPasswordResetResponse, error) {
	tokenDuration := config.GetServerConfig().JWTConfig().ExpirationTime()
	resetToken, err := p.tokenService.GenerateToken(userEmail, tokenDuration)
	if err != nil {
		return nil, err
	}

	tokenExpirationTime := time.Now().Add(tokenDuration)
	p.tokenService.AddToken(resetToken, userEmail, tokenExpirationTime)

	emailRequest := email.EmailRequest{
		Recipient: userEmail,
		PasswordResetRequest: &email.PasswordResetRequest{
			ResetToken:  resetToken,
			TokenExpiry: tokenExpirationTime,
		},
	}

	emailRequest = *p.emailService.GenerateEmail(emailRequest)
	if err := p.emailService.SendEmail(emailRequest); err != nil {
		return nil, err
	}

	response := &users.UserPasswordResetResponse{
		Message: "If an account with the given email exists, a password reset link has been sent.",
	}

	return response, nil
}
