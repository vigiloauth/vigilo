package service

import (
	"fmt"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/crypto"
	email "github.com/vigiloauth/vigilo/internal/domain/email"
	password "github.com/vigiloauth/vigilo/internal/domain/passwordreset"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
)

const (
	resetResponseMsg string = "Password reset instructions have been sent to your email if an account exists."
)

// Ensure PasswordResetService implements the PasswordReset interface.
var _ password.PasswordResetService = (*PasswordResetServiceImpl)(nil)

// PasswordResetServiceImpl provides password reset functionality.
type PasswordResetServiceImpl struct {
	tokenService   token.TokenService
	userRepository users.UserRepository
	emailService   email.EmailService
	tokenDuration  time.Duration
}

// NewPasswordResetService creates a new PasswordResetService instance.
//
// Parameters:
//
//	tokenService token.TokenService: The token service.
//	userRepository users.UserStore: The user data store.
//	emailService email.EmailService: The email service.
//
// Returns:
//
//	*PasswordResetService: A new PasswordResetService instance.
func NewPasswordResetService(
	tokenService token.TokenService,
	userRepository users.UserRepository,
	emailService email.EmailService,
) *PasswordResetServiceImpl {
	return &PasswordResetServiceImpl{
		tokenService:   tokenService,
		userRepository: userRepository,
		emailService:   emailService,
		tokenDuration:  config.GetServerConfig().TokenConfig().AccessTokenDuration(),
	}
}

// SendPasswordResetEmail sends a password reset email to the user.
//
// Parameters:
//
//	userEmail string: The user's email address.
//
// Returns:
//
//	*users.UserPasswordResetResponse: A response message.
//	error: An error if the operation fails.
func (p *PasswordResetServiceImpl) SendPasswordResetEmail(userEmail string) (*users.UserPasswordResetResponse, error) {
	if user := p.userRepository.GetUserByID(userEmail); user == nil {
		return &users.UserPasswordResetResponse{Message: resetResponseMsg}, nil
	}

	resetToken, err := p.tokenService.GenerateToken(userEmail, p.tokenDuration)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to generate reset token")
	}

	resetURL, err := p.constructResetURL(resetToken)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to construct reset URL")
	}

	if err := p.generateAndSendEmail(userEmail, resetURL, resetToken); err != nil {
		return nil, errors.Wrap(err, "", "failed to send password reset email")
	}

	p.addTokenToStore(resetToken, userEmail)
	return &users.UserPasswordResetResponse{Message: resetResponseMsg}, nil
}

// ResetPassword resets the user's password using the provided reset token.
//
// Parameters:
//
//	userEmail string: The user's email address.
//	newPassword string: The new password.
//	resetToken string: The reset token.
//
// Returns:
//
//	*users.UserPasswordResetResponse: A response message.
//	error: An error if the operation fails.
func (p *PasswordResetServiceImpl) ResetPassword(userEmail, newPassword, resetToken string) (*users.UserPasswordResetResponse, error) {
	storedToken, err := p.tokenService.ParseToken(resetToken)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to parse reset token")
	}

	if storedToken.Subject != userEmail {
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid reset token")
	}

	encryptedPassword, err := crypto.HashString(newPassword)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to encrypt password")
	}

	user := p.userRepository.GetUserByID(userEmail)
	if user == nil {
		return nil, errors.New(errors.ErrCodeUserNotFound, "user not found with the provided email address")
	}

	if user.AccountLocked {
		user.AccountLocked = false
	}

	user.Password = encryptedPassword
	if err := p.userRepository.UpdateUser(user); err != nil {
		return nil, errors.Wrap(err, "", "failed to update user")
	}

	if err := p.tokenService.DeleteToken(resetToken); err != nil {
		return nil, errors.Wrap(err, "", "failed to delete reset token")
	}

	return &users.UserPasswordResetResponse{
		Message: "Password has been reset successfully",
	}, nil
}

// constructResetURL constructs the password reset URL.
//
// Parameters:
//
//	resetToken string: The reset token.
//
// Returns:
//
//	string: The password reset URL.
//	error: An error if the base URL is not configured.
func (p *PasswordResetServiceImpl) constructResetURL(resetToken string) (string, error) {
	resetURLBase := config.GetServerConfig().BaseURL()
	if resetURLBase == "" {
		return "", errors.New(errors.ErrCodeEmptyInput, "malformed or empty base URL")
	}

	return fmt.Sprintf("%s?requestId=%s", resetURLBase, resetToken), nil
}

// generateAndSendEmail generates and sends the password reset email.
//
// Parameters:
//
//	userEmail string: The user's email address.
//	resetURL string: The password reset URL.
//	resetToken string: The reset token.
//
// Returns:
//
//	error: An error if sending the email fails.
func (p *PasswordResetServiceImpl) generateAndSendEmail(userEmail, resetURL, resetToken string) error {
	emailRequest := email.NewPasswordResetRequest(userEmail, resetURL, resetToken, time.Now().Add(p.tokenDuration))
	emailRequest = *p.emailService.GenerateEmailRequest(emailRequest)
	if err := p.emailService.SendEmail(emailRequest); err != nil {
		return errors.Wrap(err, "", "failed to send email")
	}

	return nil
}

// addTokenToStore adds the reset token to the token store.
//
// Parameters:
//
//	resetToken string: The reset token.
//	userEmail string: The user's email address.
func (p *PasswordResetServiceImpl) addTokenToStore(resetToken, userEmail string) {
	tokenExpirationTime := time.Now().Add(p.tokenDuration)
	p.tokenService.SaveToken(resetToken, userEmail, tokenExpirationTime)
}
