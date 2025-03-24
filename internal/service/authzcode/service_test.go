package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	mAuthzRepository "github.com/vigiloauth/vigilo/internal/mocks/authzcode"
	mClientService "github.com/vigiloauth/vigilo/internal/mocks/client"
	mUserService "github.com/vigiloauth/vigilo/internal/mocks/user"
)

const (
	testUserID       string = "testUserID"
	testUserPassword string = "testPassword"
	testEmail        string = "testEmail"
	testClientName   string = "testClient"
	testClientID     string = "clientID"
	testClientSecret string = "secret"
	testScope        string = "client:manage"
	testRedirectURI  string = "http://localhost/callback"
	testCode         string = "12314324code"
)

func TestAuthorizationCodeService_GenerateAuhtorizationCode(t *testing.T) {
	mockUserService := &mUserService.MockUserService{}
	mockClientService := &mClientService.MockClientService{}
	mockAuthzCodeRepo := &mAuthzRepository.MockAuthorizationCodeRepository{}

	t.Run("Success", func(t *testing.T) {
		mockUserService.GetUserByIDFunc = func(userID string) *user.User { return createTestUser() }
		mockClientService.GetClientByIDFunc = func(clientID string) *client.Client { return createTestClient() }
		mockClientService.ValidateClientRedirectURIFunc = func(redirectURI string, existingClient *client.Client) error { return nil }
		mockAuthzCodeRepo.StoreAuthorizationCodeFunc = func(code string, data *authz.AuthorizationCodeData, expiresAt time.Time) error {
			return nil
		}

		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)
		code, err := service.GenerateAuthorizationCode(testUserID, testClientID, testRedirectURI, testScope)

		assert.NoError(t, err)
		assert.NotEqual(t, "", code)
	})

	t.Run("Error is returned when missing a required paramaters", func(t *testing.T) {
		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)

		expected := errors.New(errors.ErrCodeEmptyInput, "missing one or more parameters")
		code, actual := service.GenerateAuthorizationCode("", testClientID, testRedirectURI, testScope)

		assert.Equal(t, "", code)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Error is returned when a database error occurs", func(t *testing.T) {
		mockUserService.GetUserByIDFunc = func(userID string) *user.User { return createTestUser() }
		mockClientService.GetClientByIDFunc = func(clientID string) *client.Client { return createTestClient() }
		mockClientService.ValidateClientRedirectURIFunc = func(redirectURI string, existingClient *client.Client) error { return nil }
		mockAuthzCodeRepo.StoreAuthorizationCodeFunc = func(code string, data *authz.AuthorizationCodeData, expiresAt time.Time) error {
			return errors.NewInternalServerError()
		}

		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)
		code, err := service.GenerateAuthorizationCode(testUserID, testClientID, testRedirectURI, testScope)

		assert.Error(t, err)
		assert.Equal(t, "", code)
	})

	t.Run("Error is returned when the user does not exist with the given ID", func(t *testing.T) {
		mockUserService.GetUserByIDFunc = func(userID string) *user.User { return nil }

		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)
		expected := errors.New(errors.ErrCodeUnauthorized, "invalid user_id")
		code, actual := service.GenerateAuthorizationCode(testUserID, testClientID, testRedirectURI, testScope)

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
		assert.Equal(t, "", code)
	})

	t.Run("Error is returned when the client does not exist with the given ID", func(t *testing.T) {
		mockUserService.GetUserByIDFunc = func(userID string) *user.User { return createTestUser() }
		mockClientService.GetClientByIDFunc = func(clientID string) *client.Client { return nil }

		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)
		expected := errors.New(errors.ErrCodeUnauthorized, "invalid client: invalid client_id")
		code, actual := service.GenerateAuthorizationCode(testUserID, testClientID, testRedirectURI, testScope)

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
		assert.Equal(t, "", code)
	})
}

func TestAuthorizationCodeService_ValidateAuthorizationCode(t *testing.T) {
	mockUserService := &mUserService.MockUserService{}
	mockClientService := &mClientService.MockClientService{}
	mockAuthzCodeRepo := &mAuthzRepository.MockAuthorizationCodeRepository{}

	t.Run("Success", func(t *testing.T) {
		mockAuthzCodeRepo.GetAuthorizationCodeFunc = func(code string) (*authz.AuthorizationCodeData, bool, error) {
			return createAuthzCodeData(), true, nil
		}
		mockAuthzCodeRepo.DeleteAuthorizationCodeFunc = func(code string) error { return nil }
		mockAuthzCodeRepo.UpdateAuthorizationCodeFunc = func(code string, authData *authz.AuthorizationCodeData) error {
			return nil
		}

		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)
		data, err := service.ValidateAuthorizationCode(testCode, testClientID, testRedirectURI)

		assert.NotNil(t, data)
		assert.NoError(t, err)
	})

	t.Run("Error is returned when the authorization code is not found or expired", func(t *testing.T) {
		mockAuthzCodeRepo.GetAuthorizationCodeFunc = func(code string) (*authz.AuthorizationCodeData, bool, error) {
			return nil, false, nil
		}

		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)
		expected := errors.New(errors.ErrCodeInvalidGrant, "authorization code not found or expired")
		code, actual := service.ValidateAuthorizationCode(testCode, testClientID, testRedirectURI)

		assert.Nil(t, code)
		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Error is returned when there is a client ID mismatch", func(t *testing.T) {
		mockAuthzCodeRepo.GetAuthorizationCodeFunc = func(code string) (*authz.AuthorizationCodeData, bool, error) {
			return createAuthzCodeData(), true, nil
		}

		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)
		expected := errors.New(errors.ErrCodeInvalidClient, "client ID mismatch")
		code, actual := service.ValidateAuthorizationCode(testCode, "invalidID", testRedirectURI)

		assert.Nil(t, code)
		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Error is returned when there is a redirectURI mismatch", func(t *testing.T) {
		mockAuthzCodeRepo.GetAuthorizationCodeFunc = func(code string) (*authz.AuthorizationCodeData, bool, error) {
			return createAuthzCodeData(), true, nil
		}

		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)
		expected := errors.New(errors.ErrCodeInvalidClient, "redirect URI mismatch")
		code, actual := service.ValidateAuthorizationCode(testCode, testClientID, "testRedirectURI")

		assert.Nil(t, code)
		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Error is returned when missing a required paramaters", func(t *testing.T) {
		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)

		expected := errors.New(errors.ErrCodeEmptyInput, "missing one or more parameters")
		code, actual := service.ValidateAuthorizationCode("", testClientID, testRedirectURI)

		assert.Nil(t, code)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Error is returned when there is an error deleting the code", func(t *testing.T) {
		mockAuthzCodeRepo.GetAuthorizationCodeFunc = func(code string) (*authz.AuthorizationCodeData, bool, error) {
			return createAuthzCodeData(), true, nil
		}
		mockAuthzCodeRepo.DeleteAuthorizationCodeFunc = func(code string) error {
			return errors.NewInternalServerError()
		}

		service := NewAuthorizationCodeServiceImpl(mockAuthzCodeRepo, mockUserService, mockClientService)
		data, err := service.ValidateAuthorizationCode(testCode, testClientID, testRedirectURI)

		assert.Nil(t, data)
		assert.Error(t, err)
	})
}

func createTestUser() *user.User {
	return user.NewUser(
		testUserID,
		testEmail,
		testUserPassword,
	)
}

func createTestClient() *client.Client {
	return &client.Client{
		Name:          testClientName,
		ID:            testClientID,
		Secret:        testClientSecret,
		Type:          client.Confidential,
		RedirectURIS:  []string{testRedirectURI},
		Scopes:        []string{client.ClientManage, client.ClientRead, client.ClientWrite},
		ResponseTypes: []client.ResponseType{client.CodeResponseType, client.TokenResponseType},
		GrantTypes:    []string{client.AuthorizationCode},
	}
}

func createAuthzCodeData() *authz.AuthorizationCodeData {
	return &authz.AuthorizationCodeData{
		UserID:      testUserID,
		ClientID:    testClientID,
		RedirectURI: testRedirectURI,
		Scope:       testScope,
		CreatedAt:   time.Now(),
	}
}
