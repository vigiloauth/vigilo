package service

import (
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ consent.ConsentService = (*ConsentServiceImpl)(nil)

type ConsentServiceImpl struct {
	consentRepo consent.ConsentRepository
	userRepo    users.UserRepository
}

func NewConsentServiceImpl(consentStore consent.ConsentRepository, userRepo users.UserRepository) *ConsentServiceImpl {
	return &ConsentServiceImpl{
		consentRepo: consentStore,
		userRepo:    userRepo,
	}
}

// CheckUserConsent verifies if a user has previously granted consent to a client
// for the requested scope.
//
// Parameters:
//
//	userID string: The unique identifier of the user.
//	clientID string: The identifier of the client application requesting access.
//	scope string: The space-separated list of permissions being requested.
//
// Returns:
//
//	bool: True if consent exists, false if consent is needed.
//	error: An error if the consent check operation fails.
func (c *ConsentServiceImpl) CheckUserConsent(userID, clientID, scope string) (bool, error) {
	if user := c.userRepo.GetUserByID(userID); user == nil {
		return false, errors.New(errors.ErrCodeAccessDenied, "user does not exist with the given ID")
	}

	return c.consentRepo.HasConsent(userID, clientID, scope)
}

// SaveUserConsent records a user's consent for a client application
// to access resources within the specified scope.
//
// Parameters:
//
//	userID string: The unique identifier of the user granting consent.
//	clientID string: The identifier of the client application receiving consent.
//	scope string: The space-separated list of permissions being granted.
//
// Returns:
//
//	error: An error if the consent cannot be saved, or nil if successful.
func (c *ConsentServiceImpl) SaveUserConsent(userID, clientID, scope string) error {
	if user := c.userRepo.GetUserByID(userID); user == nil {
		return errors.New(errors.ErrCodeAccessDenied, "user does not exist with the given ID")
	}

	return c.consentRepo.SaveConsent(userID, clientID, scope)
}

// RevokeConsent removes a user's consent for a client.
//
// Parameters:
//
//	userID string: The ID of the user.
//	clientID string: The ID of the client application.
//
// Returns:
//
//	error: An error if the consent cannot be revoked, or nil if successful.
func (c *ConsentServiceImpl) RevokeConsent(userID, clientID string) error {
	if user := c.userRepo.GetUserByID(userID); user == nil {
		return errors.New(errors.ErrCodeAccessDenied, "user does not exist with the given ID")
	}

	return c.consentRepo.RevokeConsent(userID, clientID)
}
