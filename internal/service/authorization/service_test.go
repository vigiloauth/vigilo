package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/errors"
	mAuthzCodeService "github.com/vigiloauth/vigilo/internal/mocks/authzcode"
	mConsentService "github.com/vigiloauth/vigilo/internal/mocks/userconsent"
)

const (
	testUserID          string = "testUserID"
	testClientID        string = "testClientID"
	testRedirectURI     string = "https://localhost/callback"
	testScope           string = "client:manage user:manage"
	testConsentApproved bool   = true
)

func TestAuthorizationService_AuthorizeClient(t *testing.T) {
	mockConsentService := &mConsentService.MockConsentService{}
	mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{}

	t.Run("Success", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(userID, clientID, redirectURI, scope string) (string, error) {
			return "code", nil
		}

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, mockConsentService)
		redirectURI, err := service.AuthorizeClient(testUserID, testClientID, testRedirectURI, testScope, "", testConsentApproved)

		assert.NoError(t, err)
		assert.NotEqual(t, "", redirectURI)
	})

	t.Run("Error is returned with the consentURL", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, mockConsentService)
		redirectURI, err := service.AuthorizeClient(testUserID, testClientID, testRedirectURI, testScope, "", false)

		assert.Error(t, err)
		assert.Equal(t, "", redirectURI)
	})

	t.Run("Error is returned generating authorization code", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(userID, clientID, redirectURI, scope string) (string, error) {
			return "", errors.NewInternalServerError()
		}

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, mockConsentService)
		redirectURI, err := service.AuthorizeClient(testUserID, testClientID, testRedirectURI, testScope, "", testConsentApproved)

		assert.Error(t, err)
		assert.Equal(t, "", redirectURI)
	})
}
