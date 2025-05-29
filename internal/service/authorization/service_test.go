package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mAuthzCodeService "github.com/vigiloauth/vigilo/v2/internal/mocks/authzcode"
	mClientService "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	mUser "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

const (
	testUserID          string = "testUserID"
	testClientID        string = "testClientID"
	testRedirectURI     string = "https://localhost/callback"
	testAuthzCode       string = "code"
	testClientSecret    string = "client-secret"
	testAccessToken     string = "access-token"
	testRefreshToken    string = "refresh-token"
	testConsentApproved bool   = true
	codeVerifier        string = "validCodeVerifier123WhichIsVeryLongAndWorks"
	testRequestID       string = "req-1234"
	testState           string = "state12345"
	testNonce           string = "nonce12345"
)

func TestAuthorizationService_AuthorizeTokenExchange(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeManager{
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
		}
		mockClientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return getTestClient(), nil
			},
		}

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService, nil, nil)
		expected := getTestAuthzCodeData()
		actual, err := service.AuthorizeTokenExchange(ctx, getTestTokenRequest())

		require.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, expected.ClientID, actual.ClientID)
		assert.Equal(t, expected.UserID, actual.UserID)
		assert.Equal(t, expected.RedirectURI, actual.RedirectURI)
		assert.Equal(t, expected.Scope, actual.Scope)
	})

	t.Run("Error is returned validating authorization code", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeManager{
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				data := getTestAuthzCodeData()
				data.Used = true
				return data, nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
		}

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, nil, nil, nil)
		actual, err := service.AuthorizeTokenExchange(ctx, getTestTokenRequest())

		require.Error(t, err)
		assert.Nil(t, actual)
	})

	t.Run("Error is returned validating client", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeManager{
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
		}
		mockClientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return nil, errors.New(errors.ErrCodeClientNotFound, "client not found")
			},
		}

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService, nil, nil)
		actual, err := service.AuthorizeTokenExchange(ctx, getTestTokenRequest())

		require.Error(t, err)
		assert.Nil(t, actual)
	})
}

func TestAuthorizationService_AuthorizeTokenExchange_PKCE(t *testing.T) {
	authzCodeData := getTestAuthzCodeData()
	authzCodeData.CodeChallenge = utils.EncodeSHA256(codeVerifier)
	ctx := context.Background()

	t.Run("Successful authorization for request using PKCE", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeManager{
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
		}
		mockClientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return getTestClient(), nil
			},
		}

		tokenRequest := getTestTokenRequest()
		tokenRequest.CodeVerifier = codeVerifier

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService, nil, nil)
		response, err := service.AuthorizeTokenExchange(ctx, tokenRequest)

		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Error is returned when token request does not have required code verifier", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeManager{
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				data := getTestAuthzCodeData()
				data.CodeChallenge = "code-challenge"
				return data, nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
		}
		mockClientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return getTestClient(), nil
			},
		}

		tokenRequest := getTestTokenRequest()
		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService, nil, nil)
		response, err := service.AuthorizeTokenExchange(ctx, tokenRequest)

		require.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestAuthorizationService_AuthorizeUserInfoRequest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		scopes := fmt.Sprintf("%s %s %s", types.OpenIDScope, types.UserEmailScope, types.UserAddressScope)
		claims := &token.TokenClaims{
			Scopes: types.Scope(scopes),
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}
		userManager := &mUser.MockUserManager{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{}, nil
			},
		}
		clientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{
					Scopes: types.ParseScopesString(scopes),
				}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, clientService, nil, userManager)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		require.NoError(t, err)
		assert.NotNil(t, retrievedUser)
	})

	t.Run("Success when 'offline_access' scope is present", func(t *testing.T) {
		scopes := fmt.Sprintf("%s %s %s %s", types.OpenIDScope, types.UserOfflineAccessScope, types.UserEmailScope, types.UserAddressScope)
		claims := &token.TokenClaims{
			Scopes: types.Scope(scopes),
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}
		userManager := &mUser.MockUserManager{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{}, nil
			},
		}
		clientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{
					Scopes: types.ParseScopesString(scopes),
				}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, clientService, nil, userManager)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		require.NoError(t, err)
		assert.NotNil(t, retrievedUser)
	})

	t.Run("Error is returned when the claims do not have sufficient scopes", func(t *testing.T) {
		claims := &token.TokenClaims{
			Scopes: types.OpenIDScope,
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}
		clientManager := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{
					ID: clientID,
				}, nil
			},
		}
		userManager := &mUser.MockUserManager{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, clientManager, nil, userManager)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		require.Error(t, err)
		assert.Nil(t, retrievedUser)
	})

	t.Run("Error is returned when the user scopes do not match the request scopes", func(t *testing.T) {
		scopes := fmt.Sprintf("%s %s %s", types.OpenIDScope, types.UserEmailScope, types.UserAddressScope)
		claims := &token.TokenClaims{
			Scopes: types.Scope(scopes),
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}
		userManager := &mUser.MockUserManager{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{}, nil
			},
		}
		clientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, clientService, nil, userManager)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		require.Error(t, err)
		assert.Nil(t, retrievedUser)
	})

	t.Run("Error is return when user session is not present", func(t *testing.T) {
		scopes := fmt.Sprintf("%s %s %s", types.OpenIDScope, types.UserEmailScope, types.UserAddressScope)
		claims := &token.TokenClaims{
			Scopes: types.Scope(scopes),
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}
		userManager := &mUser.MockUserManager{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{}, nil
			},
		}
		clientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, clientService, nil, userManager)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		require.Error(t, err)
		assert.Nil(t, retrievedUser)
	})
}

func getTestAuthzCodeData() *authzCode.AuthorizationCodeData {
	scopes := fmt.Sprintf("%s %s", types.OpenIDScope, types.UserAddressScope)
	return &authzCode.AuthorizationCodeData{
		UserID:      testUserID,
		ClientID:    testClientID,
		RedirectURI: testRedirectURI,
		Scope:       types.Scope(scopes),
	}
}

func getTestClient() *client.Client {
	return &client.Client{
		ID:            testClientID,
		Secret:        testClientSecret,
		Type:          types.ConfidentialClient,
		RedirectURIs:  []string{testClientID},
		Scopes:        []types.Scope{types.OpenIDScope, types.UserAddressScope},
		GrantTypes:    []string{constants.AuthorizationCodeGrantType},
		ResponseTypes: []string{constants.CodeResponseType},
		RequiresPKCE:  true,
	}
}

func getTestTokenRequest() *token.TokenRequest {
	return &token.TokenRequest{
		GrantType:         constants.AuthorizationCodeGrantType,
		AuthorizationCode: testAuthzCode,
		RedirectURI:       testRedirectURI,
		ClientID:          testClientID,
		ClientSecret:      testClientSecret,
	}
}
