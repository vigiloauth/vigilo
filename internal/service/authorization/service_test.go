package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/constants"
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
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(ctx context.Context, userID, clientID, scope string) (bool, error) {
			return true, nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
			return "code", nil
		}
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return getTestClient(), nil
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationService(mockAuthzCodeService, mockConsentService, nil, mockClientService)
		redirectURI, err := service.AuthorizeClient(ctx, request, testConsentApproved)

		assert.NoError(t, err)
		assert.NotEqual(t, "", redirectURI)
	})

	t.Run("Error is returned generating authorization code", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(ctx context.Context, userID, clientID, scope string) (bool, error) {
			return true, nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
			return "", errors.NewInternalServerError()
		}
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return getTestClient(), nil
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationService(mockAuthzCodeService, mockConsentService, nil, mockClientService)
		redirectURI, err := service.AuthorizeClient(ctx, request, testConsentApproved)

		assert.Error(t, err)
		assert.Equal(t, "", redirectURI)
	})

	t.Run("Error is returned when user does not provide consent", func(t *testing.T) {
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return getTestClient(), nil
		}
		mockConsentService.CheckUserConsentFunc = func(ctx context.Context, userID, clientID, scope string) (bool, error) {
			return false, errors.NewAccessDeniedError()
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationService(nil, mockConsentService, nil, mockClientService)

		_, err := service.AuthorizeClient(ctx, request, true)
		expectedErr := "the resource owner denied the request"

		assert.Error(t, err)
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Error is returned when the client authorization code request is invalid", func(t *testing.T) {
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return getTestClient(), nil
		}

		request := &client.ClientAuthorizationRequest{
			Client: &client.Client{
				GrantTypes:    []string{constants.AuthorizationCode, constants.PKCE},
				ResponseTypes: []string{constants.IDTokenResponseType},
			},
			CodeChallenge: "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_",
		}

		service := NewAuthorizationService(nil, nil, nil, mockClientService)
		_, err := service.AuthorizeClient(ctx, request, true)

		assert.Error(t, err)
	})

	t.Run("Consent required error is returned when the user does not approve consent and consent is required", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(ctx context.Context, userID, clientID, scope string) (bool, error) {
			return true, nil
		}
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return getTestClient(), nil
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationService(nil, mockConsentService, nil, mockClientService)

		_, err := service.AuthorizeClient(ctx, request, false)

		assert.Contains(t, "user consent required for the requested scope", err.Error())
		assert.Error(t, err)
	})

	t.Run("Access denied error is returned when consent is approved but user denies consent", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(ctx context.Context, userID, clientID, scope string) (bool, error) {
			return false, nil
		}
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return getTestClient(), nil
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationService(nil, mockConsentService, nil, mockClientService)

		_, err := service.AuthorizeClient(ctx, request, true)

		assert.Contains(t, "the resource owner denied the request", err.Error())
		assert.Error(t, err)
	})
}

func TestAuthorizationService_AuthorizeTokenExchange(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(ctx context.Context, ode, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			RevokeAuthorizationCodeFunc: func(ctx context.Context, code string) error { return nil },
		}

		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return getTestClient(), nil
			},
		}

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService)
		expected := getTestAuthzCodeData()
		actual, err := service.AuthorizeTokenExchange(ctx, getTestTokenRequest())

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, expected.ClientID, actual.ClientID)
		assert.Equal(t, expected.UserID, actual.UserID)
		assert.Equal(t, expected.RedirectURI, actual.RedirectURI)
		assert.Equal(t, expected.Scope, actual.Scope)
	})

	t.Run("Error is returned validating authorization code", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(ctx context.Context, code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return nil, errors.New(errors.ErrCodeInvalidGrant, "invalid authorization code")
			},
			RevokeAuthorizationCodeFunc: func(ctx context.Context, code string) error { return nil },
		}

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, nil)
		expected := "failed to validate authorization code: invalid authorization code"
		actual, err := service.AuthorizeTokenExchange(ctx, getTestTokenRequest())

		assert.Error(t, err)
		assert.Equal(t, expected, err.Error())
		assert.Nil(t, actual)
	})

	t.Run("Error is returned validating client", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(ctx context.Context, code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			RevokeAuthorizationCodeFunc: func(ctx context.Context, code string) error { return nil },
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return nil, nil
			},
		}

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService)
		expected := "failed to validate client: invalid client"
		actual, err := service.AuthorizeTokenExchange(ctx, getTestTokenRequest())

		assert.Error(t, err)
		assert.Equal(t, expected, err.Error())
		assert.Nil(t, actual)
	})
}

func TestAuthorizationService_AuthorizeTokenExchange_PKCE(t *testing.T) {
	authzCodeData := getTestAuthzCodeData()
	authzCodeData.CodeChallenge = crypto.EncodeSHA256(codeVerifier)
	ctx := context.Background()

	t.Run("Successful authorization for request using PKCE", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(ctx context.Context, code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return authzCodeData, nil
			},
			ValidatePKCEFunc: func(authzCodeData *authzCode.AuthorizationCodeData, codeVerifier string) error {
				return nil
			},
			RevokeAuthorizationCodeFunc: func(ctx context.Context, code string) error { return nil },
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return getTestClient(), nil
			},
		}

		tokenRequest := getTestTokenRequest()
		tokenRequest.CodeVerifier = codeVerifier

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService)
		response, err := service.AuthorizeTokenExchange(ctx, tokenRequest)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Error is returned when token request does not have required code verifier", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(ctx context.Context, code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return authzCodeData, nil
			},
			ValidatePKCEFunc: func(authzCodeData *authzCode.AuthorizationCodeData, codeVerifier string) error {
				return nil
			},
			RevokeAuthorizationCodeFunc: func(ctx context.Context, code string) error { return nil },
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return getTestClient(), nil
			},
		}

		tokenRequest := getTestTokenRequest()
		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService)

		expectedErr := "missing code verifier for PKCE"
		response, err := service.AuthorizeTokenExchange(ctx, tokenRequest)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), expectedErr)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when validating PKCE request", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			ValidateAuthorizationCodeFunc: func(ctx context.Context, code, clientID, redirectURI string) (*authzCode.AuthorizationCodeData, error) {
				return authzCodeData, nil
			},
			ValidatePKCEFunc: func(authzCodeData *authzCode.AuthorizationCodeData, codeVerifier string) error {
				return errors.New(errors.ErrCodeInvalidGrant, "PKCE validation failed")
			},
			RevokeAuthorizationCodeFunc: func(ctx context.Context, code string) error { return nil },
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return getTestClient(), nil
			},
		}

		tokenRequest := getTestTokenRequest()
		tokenRequest.CodeVerifier = codeVerifier
		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService)

		response, err := service.AuthorizeTokenExchange(ctx, tokenRequest)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PKCE validation failed")
		assert.Nil(t, response)
	})
}

func TestAuthorizationService_GenerateTokens(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokensWithAudienceFunc: func(ctx context.Context, userID, clientID, scopes string) (string, string, error) {
				return testAccessToken, testRefreshToken, nil
			},
		}

		service := NewAuthorizationService(nil, nil, mockTokenService, nil)
		expected := &token.TokenResponse{
			AccessToken:  testAccessToken,
			RefreshToken: testRefreshToken,
			TokenType:    token.BearerToken,
		}

		actual, err := service.GenerateTokens(ctx, getTestAuthzCodeData())

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, expected.AccessToken, actual.AccessToken)
		assert.Equal(t, expected.RefreshToken, actual.RefreshToken)
		assert.Equal(t, expected.TokenType, actual.TokenType)
	})

	t.Run("Error is returned generating access token", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokensWithAudienceFunc: func(ctx context.Context, userID, clientID, scopes string) (string, string, error) {
				return "", "", errors.NewInternalServerError()
			},
		}

		service := NewAuthorizationService(nil, nil, mockTokenService, nil)
		expected := "failed to generate tokens: An unexpected error occurred. Please try again later."
		_, err := service.GenerateTokens(ctx, getTestAuthzCodeData())

		assert.Error(t, err)
		assert.Equal(t, expected, err.Error())
	})
}

func getClientAuthorizationRequest() *client.ClientAuthorizationRequest {
	return &client.ClientAuthorizationRequest{
		ClientID:            testClientID,
		ResponseType:        constants.CodeResponseType,
		RedirectURI:         testRedirectURI,
		Scope:               constants.ClientManage,
		State:               "testState",
		CodeChallenge:       "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_",
		CodeChallengeMethod: client.S256,
		UserID:              testUserID,
		Client: &client.Client{
			Name:          "Test Client",
			Type:          constants.PKCE,
			RedirectURIS:  []string{testRedirectURI},
			GrantTypes:    []string{constants.AuthorizationCode, constants.PKCE},
			Scopes:        []string{constants.ClientManage},
			ResponseTypes: []string{constants.CodeResponseType},
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
		Scopes:        []string{constants.ClientManage, constants.UserRead},
		GrantTypes:    []string{constants.AuthorizationCode, constants.PKCE},
		ResponseTypes: []string{constants.CodeResponseType},
	}
}

func getTestTokenRequest() *token.TokenRequest {
	return &token.TokenRequest{
		GrantType:         constants.AuthorizationCode,
		AuthorizationCode: testAuthzCode,
		RedirectURI:       testRedirectURI,
		ClientID:          testClientID,
		ClientSecret:      testClientSecret,
	}
}
