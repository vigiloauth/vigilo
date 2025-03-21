package auth

import (
	"fmt"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/email"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

const (
	tokenDuration    time.Duration = 15 * time.Minute                                                                 // Duration for password reset tokens.
	resetResponseMsg string        = "Password reset instructions have been sent to your email if an account exists." // Generic response message.
)

// PasswordReset defines the interface for password reset operations.
type PasswordReset interface {
	SendPasswordResetEmail(userEmail string) (*users.UserPasswordResetResponse, error)
	ResetPassword(userEmail, newPassword, resetToken string) (*users.UserPasswordResetResponse, error)
}

// Ensure PasswordResetService implements the PasswordReset interface.
var _ PasswordReset = (*PasswordResetService)(nil)

// PasswordResetService provides password reset functionality.
type PasswordResetService struct {
	tokenManager token.TokenService // Token manager for JWT.
	userStore    users.UserStore    // User data store.
	emailService email.EmailService // Email service for sending reset emails.
}

// NewPasswordResetService creates a new PasswordResetService instance.
//
// Parameters:
//
//	tokenManager token.TokenManager: The token manager.
//	userStore users.UserStore: The user data store.
//	emailService email.EmailService: The email service.
//
// Returns:
//
//	*PasswordResetService: A new PasswordResetService instance.
func NewPasswordResetService(tokenManager token.TokenService, userStore users.UserStore, emailService email.EmailService) *PasswordResetService {
	return &PasswordResetService{
		tokenManager: tokenManager,
		userStore:    userStore,
		emailService: emailService,
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
func (p *PasswordResetService) SendPasswordResetEmail(userEmail string) (*users.UserPasswordResetResponse, error) {
	if user := p.userStore.GetUser(userEmail); user == nil {
		return &users.UserPasswordResetResponse{Message: resetResponseMsg}, nil
	}

	resetToken, err := p.tokenManager.GenerateToken(userEmail, tokenDuration)
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
func (p *PasswordResetService) ResetPassword(userEmail, newPassword, resetToken string) (*users.UserPasswordResetResponse, error) {
	storedToken, err := p.tokenManager.ParseToken(resetToken)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to parse reset token")
	}

	if storedToken.Subject != userEmail {
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid reset token")
	}

	encryptedPassword, err := utils.HashString(newPassword)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to encrypt password")
	}

	user := p.userStore.GetUser(userEmail)
	if user == nil {
		return nil, errors.New(errors.ErrCodeUserNotFound, "user not found with the provided email address")
	}

	if user.AccountLocked {
		user.AccountLocked = false
	}

	user.Password = encryptedPassword
	if err := p.userStore.UpdateUser(user); err != nil {
		return nil, errors.Wrap(err, "", "failed to update user")
	}

	if err := p.tokenManager.DeleteToken(resetToken); err != nil {
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
func (p *PasswordResetService) constructResetURL(resetToken string) (string, error) {
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
func (p *PasswordResetService) generateAndSendEmail(userEmail, resetURL, resetToken string) error {
	emailRequest := email.NewPasswordResetRequest(userEmail, resetURL, resetToken, time.Now().Add(tokenDuration))
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
func (p *PasswordResetService) addTokenToStore(resetToken, userEmail string) {
	tokenExpirationTime := time.Now().Add(tokenDuration)
	p.tokenManager.SaveToken(resetToken, userEmail, tokenExpirationTime)
}
