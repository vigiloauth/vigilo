package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	mUserRepo "github.com/vigiloauth/vigilo/internal/mocks/user"
	mConsentRepo "github.com/vigiloauth/vigilo/internal/mocks/userconsent"
)

const (
	testUserID   string = "user_id"
	testClientID string = "client_id"
	testScope    string = "user:read"
)

func TestConsentService_CheckUserConsent(t *testing.T) {
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}
	mockUserRepo := &mUserRepo.MockUserRepository{}

	t.Run("Returns true when user has consent", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.HasConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}

		cs := NewConsentServiceImpl(mockConsentRepo, mockUserRepo)
		hasConsent, err := cs.CheckUserConsent(testUserID, testClientID, testScope)

		assert.NoError(t, err)
		assert.True(t, hasConsent)
	})

	t.Run("Returns false when user does not have consent", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.HasConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return false, nil
		}

		cs := NewConsentServiceImpl(mockConsentRepo, mockUserRepo)
		hasConsent, err := cs.CheckUserConsent(testUserID, testClientID, testScope)

		assert.NoError(t, err)
		assert.False(t, hasConsent)
	})

	t.Run("Error is returned when a database error occurs", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return nil }
		mockConsentRepo.HasConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, errors.NewInternalServerError()
		}

		cs := NewConsentServiceImpl(mockConsentRepo, mockUserRepo)
		hasConsent, err := cs.CheckUserConsent(testUserID, testClientID, testScope)

		assert.Error(t, err)
		assert.False(t, hasConsent)
	})
}

func TestConsentService_SaveUserConsent(t *testing.T) {
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}
	mockUserRepo := &mUserRepo.MockUserRepository{}

	t.Run("Success", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.SaveConsentFunc = func(userID, clientID, scope string) error { return nil }

		cs := NewConsentServiceImpl(mockConsentRepo, mockUserRepo)
		err := cs.SaveUserConsent(testUserID, testClientID, testScope)

		assert.NoError(t, err)
	})

	t.Run("Error is returned when a database error occurs", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.SaveConsentFunc = func(userID, clientID, scope string) error {
			return errors.NewInternalServerError()
		}

		cs := NewConsentServiceImpl(mockConsentRepo, mockUserRepo)
		err := cs.SaveUserConsent(testUserID, testClientID, testScope)

		assert.Error(t, err)
	})

	t.Run("Error is returned when the user does not exist", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return nil }

		cs := NewConsentServiceImpl(mockConsentRepo, mockUserRepo)
		err := cs.SaveUserConsent(testUserID, testClientID, testScope)

		assert.Error(t, err)
	})
}

func TestConsentService_RevokeUserConsent(t *testing.T) {
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}
	mockUserRepo := &mUserRepo.MockUserRepository{}

	t.Run("Consent is successfully revoked", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.RevokeConsentFunc = func(userID, clientID string) error { return nil }

		cs := NewConsentServiceImpl(mockConsentRepo, mockUserRepo)
		err := cs.RevokeConsent(testUserID, testClientID)

		assert.NoError(t, err)
	})

	t.Run("Error is returned when there is an error revoking consent", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.RevokeConsentFunc = func(userID, clientID string) error {
			return errors.NewInternalServerError()
		}

		cs := NewConsentServiceImpl(mockConsentRepo, mockUserRepo)
		err := cs.RevokeConsent(testUserID, testClientID)

		assert.Error(t, err)
	})

	t.Run("Error is returned when the user does not exist", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return nil }

		cs := NewConsentServiceImpl(mockConsentRepo, mockUserRepo)
		err := cs.RevokeConsent(testUserID, testClientID)

		assert.Error(t, err)
	})
}
