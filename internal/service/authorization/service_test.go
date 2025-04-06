package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/crypto"
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
	codeVerifier        string = "validCodeVerifier123WhichIsVeryLongAndWorks"
)

func TestAuthorizationService_AuthorizeClient(t *testing.T) {
	mockConsentService := &mConsentService.MockUserConsentService{}
	mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{}
	mockClientService := &mClientService.MockClientService{}

	t.Run("Success", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(req *client.ClientAuthorizationRequest) (string, error) {
			return "code", nil
		}
		mockClientService.GetClientByIDFunc = func(clientID string) *client.Client {
			return getTestClient()
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationServiceImpl(mockAuthzCodeService, mockConsentService, nil, mockClientService)
		redirectURI, err := service.AuthorizeClient(request, testConsentApproved)

		assert.NoError(t, err)
		assert.NotEqual(t, "", redirectURI)
	})

	t.Run("Error is returned generating authorization code", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(req *client.ClientAuthorizationRequest) (string, error) {
			return "", errors.NewInternalServerError()
		}
		mockClientService.GetClientByIDFunc = func(clientID string) *client.Client {
			return getTestClient()
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationServiceImpl(mockAuthzCodeService, mockConsentService, nil, mockClientService)
		redirectURI, err := service.AuthorizeClient(request, testConsentApproved)

		assert.Error(t, err)
		assert.Equal(t, "", redirectURI)
	})

	t.Run("Error is returned when user does not provide consent", func(t *testing.T) {
		mockClientService.GetClientByIDFunc = func(clientID string) *client.Client {
			return getTestClient()
		}
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return false, errors.NewAccessDeniedError()
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationServiceImpl(nil, mockConsentService, nil, mockClientService)

		_, err := service.AuthorizeClient(request, true)
		expectedErr := "the resource owner denied the request"

		assert.Error(t, err)
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Error is returned when the client authorization code request is invalid", func(t *testing.T) {
		mockClientService.GetClientByIDFunc = func(clientID string) *client.Client {
			return getTestClient()
		}

		request := &client.ClientAuthorizationRequest{
			Client: &client.Client{
				GrantTypes:    []string{client.AuthorizationCode, client.PKCE},
				ResponseTypes: []string{client.IDTokenResponseType},
			},
			CodeChallenge: "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_",
		}

		service := NewAuthorizationServiceImpl(nil, nil, nil, mockClientService)
		_, err := service.AuthorizeClient(request, true)

		assert.Error(t, err)
	})

	t.Run("Consent required error is returned when the user does not approve consent and consent is required", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}
		mockClientService.GetClientByIDFunc = func(clientID string) *client.Client {
			return getTestClient()
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationServiceImpl(nil, mockConsentService, nil, mockClientService)

		_, err := service.AuthorizeClient(request, false)

		assert.Contains(t, "user consent required for the requested scope", err.Error())
		assert.Error(t, err)
	})

	t.Run("Access denied error is returned when consent is approved but user denies consent", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return false, nil
		}
		mockClientService.GetClientByIDFunc = func(clientID string) *client.Client {
			return getTestClient()
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationServiceImpl(nil, mockConsentService, nil, mockClientService)

		_, err := service.AuthorizeClient(request, true)

		assert.Contains(t, "the resource owner denied the request", err.Error())
		assert.Error(t, err)
	})
}

func TestAuthorizationService_AuthorizeTokenExchange(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			GetAuthorizationCodeFunc: func(code string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			RevokeAuthorizationCodeFunc: func(code string) error { return nil },
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
			RevokeAuthorizationCodeFunc: func(code string) error { return nil },
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
			RevokeAuthorizationCodeFunc: func(code string) error { return nil },
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

func TestAuthorizationService_AuthorizeTokenExchange_PKCE(t *testing.T) {
	authzCodeData := getTestAuthzCodeData()
	authzCodeData.CodeChallenge = crypto.HashSHA256(codeVerifier)

	t.Run("Successful authorization for request using PKCE", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return authzCodeData, nil
			},
			ValidatePKCEFunc: func(authzCodeData *authzCode.AuthorizationCodeData, codeVerifier string) error {
				return nil
			},
			RevokeAuthorizationCodeFunc: func(code string) error { return nil },
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return getTestClient()
			},
		}

		tokenRequest := getTestTokenRequest()
		tokenRequest.CodeVerifier = codeVerifier

		service := NewAuthorizationServiceImpl(mockAuthzCodeService, nil, nil, mockClientService)
		response, err := service.AuthorizeTokenExchange(tokenRequest)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Error is returned when token request does not have required code verifier", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return authzCodeData, nil
			},
			ValidatePKCEFunc: func(authzCodeData *authzCode.AuthorizationCodeData, codeVerifier string) error {
				return nil
			},
			RevokeAuthorizationCodeFunc: func(code string) error { return nil },
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return getTestClient()
			},
		}

		tokenRequest := getTestTokenRequest()
		service := NewAuthorizationServiceImpl(mockAuthzCodeService, nil, nil, mockClientService)

		expectedErr := "missing code verifier for PKCE"
		response, err := service.AuthorizeTokenExchange(tokenRequest)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), expectedErr)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when validating PKCE request", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return authzCodeData, nil
			},
			ValidatePKCEFunc: func(authzCodeData *authzCode.AuthorizationCodeData, codeVerifier string) error {
				return errors.New(errors.ErrCodeInvalidGrant, "PKCE validation failed")
			},
			RevokeAuthorizationCodeFunc: func(code string) error { return nil },
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return getTestClient()
			},
		}

		tokenRequest := getTestTokenRequest()
		tokenRequest.CodeVerifier = codeVerifier
		service := NewAuthorizationServiceImpl(mockAuthzCodeService, nil, nil, mockClientService)

		response, err := service.AuthorizeTokenExchange(tokenRequest)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PKCE validation failed")
		assert.Nil(t, response)
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

func getClientAuthorizationRequest() *client.ClientAuthorizationRequest {
	return &client.ClientAuthorizationRequest{
		ClientID:            testClientID,
		ResponseType:        client.CodeResponseType,
		RedirectURI:         testRedirectURI,
		Scope:               client.ClientManage,
		State:               "testState",
		CodeChallenge:       "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_",
		CodeChallengeMethod: client.S256,
		UserID:              testUserID,
		Client: &client.Client{
			Name:          "Test Client",
			Type:          client.PKCE,
			RedirectURIS:  []string{testRedirectURI},
			GrantTypes:    []string{client.AuthorizationCode, client.PKCE},
			Scopes:        []string{client.ClientManage},
			ResponseTypes: []string{client.CodeResponseType},
		},
	}
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
		ID:            testClientID,
		Secret:        testClientSecret,
		RedirectURIS:  []string{testClientID},
		Scopes:        []string{client.ClientManage, client.UserRead},
		GrantTypes:    []string{client.AuthorizationCode, client.PKCE},
		ResponseTypes: []string{client.CodeResponseType},
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
