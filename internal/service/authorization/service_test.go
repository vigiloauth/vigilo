package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	authzCode "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	mAuthzCodeService "github.com/vigiloauth/vigilo/internal/mocks/authzcode"
	mClientService "github.com/vigiloauth/vigilo/internal/mocks/client"
	mTokenService "github.com/vigiloauth/vigilo/internal/mocks/token"
	mConsentService "github.com/vigiloauth/vigilo/internal/mocks/userconsent"
)

const (
	testUserID          string = "testUserID"
	testClientID        string = "testClientID"
	testRedirectURI     string = "https://localhost/callback"
	testScope           string = "client:manage user:manage"
	testAuthzCode       string = "code"
	testClientSecret    string = "client-secret"
	testAccessToken     string = "access-token"
	testRefreshToken    string = "refresh-token"
	testConsentApproved bool   = true
)

func TestAuthorizationService_AuthorizeClient(t *testing.T) {
	mockConsentService := &mConsentService.MockUserConsentService{}
	mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{}
	mockTokenService := &mTokenService.MockTokenService{}
	mockClientService := &mClientService.MockClientService{}

	t.Run("Success", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(userID, clientID, redirectURI, scope string) (string, error) {
			return "code", nil
		}

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, mockConsentService, mockTokenService, mockClientService)
		redirectURI, err := service.AuthorizeClient(testUserID, testClientID, testRedirectURI, testScope, "", testConsentApproved)

		assert.NoError(t, err)
		assert.NotEqual(t, "", redirectURI)
	})

	t.Run("Error is returned with the consentURL", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, mockConsentService, mockTokenService, mockClientService)
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

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, mockConsentService, mockTokenService, mockClientService)
		redirectURI, err := service.AuthorizeClient(testUserID, testClientID, testRedirectURI, testScope, "", testConsentApproved)

		assert.Error(t, err)
		assert.Equal(t, "", redirectURI)
	})
}

func TestAuthorizationService_AuthorizeTokenExchange(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			GetAuthorizationCodeFunc: func(code string) *authzCode.AuthorizationCodeData {
				return getTestAuthzCodeData()
			},
		}

		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return getTestClient()
			},
		}

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, nil, nil, mockClientService)
		expected := getTestAuthzCodeData()
		actual, err := service.AuthorizeTokenExchange(getTestTokenRequest())

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, expected.ClientID, actual.ClientID)
		assert.Equal(t, expected.UserID, actual.UserID)
		assert.Equal(t, expected.RedirectURI, actual.RedirectURI)
		assert.Equal(t, expected.Scope, actual.Scope)
	})

	t.Run("Error is returned validating authorization code", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return nil, errors.New(errors.ErrCodeInvalidGrant, "invalid authorization code")
			},
		}

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, nil, nil, nil)
		expected := "failed to validate authorization code: invalid authorization code"
		actual, err := service.AuthorizeTokenExchange(getTestTokenRequest())

		assert.Error(t, err)
		assert.Equal(t, expected, err.Error())
		assert.Nil(t, actual)
	})

	t.Run("Error is returned validating client", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return nil
			},
		}

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, nil, nil, mockClientService)
		expected := "failed to validate client: invalid client"
		actual, err := service.AuthorizeTokenExchange(getTestTokenRequest())

		assert.Error(t, err)
		assert.Equal(t, expected, err.Error())
		assert.Nil(t, actual)
	})
}

func TestAuthorizationService_GenerateTokens(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokenPairFunc: func(userID string, clientID string) (string, string, error) {
				return testAccessToken, testRefreshToken, nil
			},
		}

		service := NewAuthorizationServiceImpl(nil, nil, mockTokenService, nil)
		expected := &token.TokenResponse{
			AccessToken:  testAccessToken,
			RefreshToken: testRefreshToken,
			TokenType:    token.BearerToken,
		}

		actual, err := service.GenerateTokens(getTestAuthzCodeData())

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, expected.AccessToken, actual.AccessToken)
		assert.Equal(t, expected.RefreshToken, actual.RefreshToken)
		assert.Equal(t, expected.TokenType, actual.TokenType)
	})

	t.Run("Error is returned generating access token", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokenPairFunc: func(userID string, clientID string) (string, string, error) {
				return "", "", errors.NewInternalServerError()
			},
		}

		service := NewAuthorizationServiceImpl(nil, nil, mockTokenService, nil)
		expected := "failed to generate tokens: An unexpected error occurred. Please try again later."
		_, err := service.GenerateTokens(getTestAuthzCodeData())

		assert.Error(t, err)
		assert.Equal(t, expected, err.Error())
	})
}

func getTestAuthzCodeData() *authzCode.AuthorizationCodeData {
	return &authzCode.AuthorizationCodeData{
		UserID:      testUserID,
		ClientID:    testClientID,
		RedirectURI: testRedirectURI,
		Scope:       testScope,
	}
}

func getTestClient() *client.Client {
	return &client.Client{
		ID:           testClientID,
		Secret:       testClientSecret,
		RedirectURIS: []string{testClientID},
		Scopes:       []string{"clientL:manage", "user:manage"},
	}
}

func getTestTokenRequest() *token.TokenRequest {
	return &token.TokenRequest{
		GrantType:         client.AuthorizationCode,
		AuthorizationCode: testAuthzCode,
		RedirectURI:       testRedirectURI,
		ClientID:          testClientID,
		ClientSecret:      testClientSecret,
	}
}
