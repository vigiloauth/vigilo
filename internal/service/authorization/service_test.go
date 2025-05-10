package service

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mAuthzCodeService "github.com/vigiloauth/vigilo/v2/internal/mocks/authzcode"
	mClientService "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	mSessionService "github.com/vigiloauth/vigilo/v2/internal/mocks/session"
	mTokenService "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	mUser "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
	mConsentService "github.com/vigiloauth/vigilo/v2/internal/mocks/userconsent"
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
	mockSessionService := &mSessionService.MockSessionService{}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockConsentService.CheckUserConsentFunc = func(ctx context.Context, userID, clientID, scope string) (bool, error) {
			return false, nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
			return "code", nil
		}
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return getTestClient(), nil
		}
		mockSessionService.GetOrCreateSessionFunc = func(ctx context.Context, w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) (*session.SessionData, error) {
			sessionData.UserID = "user_id"
			return sessionData, nil
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationService(mockAuthzCodeService, mockConsentService, nil, mockClientService, nil, mockSessionService)
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
		mockSessionService.GetOrCreateSessionFunc = func(ctx context.Context, w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) (*session.SessionData, error) {
			sessionData.UserID = "user_id"
			return sessionData, nil
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationService(mockAuthzCodeService, mockConsentService, nil, mockClientService, nil, mockSessionService)
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
		mockSessionService.GetOrCreateSessionFunc = func(ctx context.Context, w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) (*session.SessionData, error) {
			sessionData.UserID = "user_id"
			return sessionData, nil
		}

		request := getClientAuthorizationRequest()
		service := NewAuthorizationService(nil, mockConsentService, nil, mockClientService, nil, mockSessionService)

		_, err := service.AuthorizeClient(ctx, request, true)
		expectedErr := "the resource owner denied the request"

		assert.Error(t, err)
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Error is returned when the client authorization code request is invalid", func(t *testing.T) {
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return getTestClient(), nil
		}
		mockSessionService.GetOrCreateSessionFunc = func(ctx context.Context, w http.ResponseWriter, r *http.Request, sessionData *session.SessionData) (*session.SessionData, error) {
			sessionData.UserID = "user_id"
			return sessionData, nil
		}

		request := &client.ClientAuthorizationRequest{
			Client: &client.Client{
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
				RequiresPKCE:  true,
				ResponseTypes: []string{constants.IDTokenResponseType},
			},
			CodeChallenge: "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_",
		}

		service := NewAuthorizationService(nil, nil, nil, mockClientService, nil, mockSessionService)
		_, err := service.AuthorizeClient(ctx, request, true)

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

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService, nil, nil)
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

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, nil, nil, nil)
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

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService, nil, nil)
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

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService, nil, nil)
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
		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService, nil, nil)

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
		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, mockClientService, nil, nil)

		response, err := service.AuthorizeTokenExchange(ctx, tokenRequest)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "PKCE validation failed")
		assert.Nil(t, response)
	})
}

func TestAuthorizationService_GenerateTokens(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{ID: clientID, Type: client.Confidential}, nil
			},
		}
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokensWithAudienceFunc: func(ctx context.Context, userID, clientID, scopes, roles string) (string, string, error) {
				return testAccessToken, testRefreshToken, nil
			},
			GenerateIDTokenFunc: func(ctx context.Context, userID, clientID, scopes, nonce string) (string, error) {
				return "idToken", nil
			},
		}

		service := NewAuthorizationService(nil, nil, mockTokenService, mockClientService, nil, nil)

		actual, err := service.GenerateTokens(ctx, getTestAuthzCodeData())

		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})

	t.Run("Error is returned generating access token", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokensWithAudienceFunc: func(ctx context.Context, userID, clientID, scopes, roles string) (string, string, error) {
				return "", "", errors.NewInternalServerError()
			},
		}

		service := NewAuthorizationService(nil, nil, mockTokenService, nil, nil, nil)
		expected := "failed to generate tokens: An unexpected error occurred. Please try again later."
		_, err := service.GenerateTokens(ctx, getTestAuthzCodeData())

		assert.Error(t, err)
		assert.Equal(t, expected, err.Error())
	})
}

func TestAuthorizationService_AuthorizeUserInfoRequest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		scopes := fmt.Sprintf("%s %s %s", constants.OpenIDScope, constants.UserEmailScope, constants.UserAddressScope)
		claims := &token.TokenClaims{
			Scopes: scopes,
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}

		userService := &mUser.MockUserService{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{
					Scopes: strings.Split(scopes, " "),
				}, nil
			},
		}
		clientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{
					Scopes: strings.Split(scopes, " "),
				}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, clientService, userService, nil)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		assert.NoError(t, err)
		assert.NotNil(t, retrievedUser)
	})

	t.Run("Success when 'offline_access' scope is present", func(t *testing.T) {
		scopes := fmt.Sprintf("%s %s %s %s", constants.OpenIDScope, constants.UserOfflineAccessScope, constants.UserEmailScope, constants.UserAddressScope)
		claims := &token.TokenClaims{
			Scopes: scopes,
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}

		userService := &mUser.MockUserService{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{
					Scopes: strings.Split(scopes, " "),
				}, nil
			},
		}
		clientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{
					Scopes: strings.Split(scopes, " "),
				}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, clientService, userService, nil)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		assert.NoError(t, err)
		assert.NotNil(t, retrievedUser)
	})

	t.Run("Error is returned when the claims do not have sufficient scopes", func(t *testing.T) {
		claims := &token.TokenClaims{
			Scopes: constants.ClientDeleteScope,
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}

		userService := &mUser.MockUserService{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, nil, userService, nil)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		assert.Error(t, err)
		assert.Nil(t, retrievedUser)
	})

	t.Run("Error is returned when the user scopes do not match the request scopes", func(t *testing.T) {
		scopes := fmt.Sprintf("%s %s %s", constants.OpenIDScope, constants.UserEmailScope, constants.UserAddressScope)
		claims := &token.TokenClaims{
			Scopes: scopes,
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}

		userService := &mUser.MockUserService{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{
					Scopes: []string{constants.UserPhoneScope},
				}, nil
			},
		}
		clientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, clientService, userService, nil)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		assert.Error(t, err)
		assert.Nil(t, retrievedUser)
	})

	t.Run("Error is return when user session is not present", func(t *testing.T) {
		scopes := fmt.Sprintf("%s %s %s", constants.OpenIDScope, constants.UserEmailScope, constants.UserAddressScope)
		claims := &token.TokenClaims{
			Scopes: scopes,
			StandardClaims: &jwt.StandardClaims{
				Subject:  testUserID,
				Audience: testClientID,
			},
		}

		userService := &mUser.MockUserService{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{
					Scopes: []string{constants.UserPhoneScope},
				}, nil
			},
		}
		clientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{}, nil
			},
		}

		service := NewAuthorizationService(nil, nil, nil, clientService, userService, nil)
		retrievedUser, err := service.AuthorizeUserInfoRequest(context.Background(), claims)

		assert.Error(t, err)
		assert.Nil(t, retrievedUser)
	})
}

func getClientAuthorizationRequest() *client.ClientAuthorizationRequest {
	return &client.ClientAuthorizationRequest{
		ClientID:            testClientID,
		ResponseType:        constants.CodeResponseType,
		RedirectURI:         testRedirectURI,
		Scope:               constants.ClientManageScope,
		State:               "testState",
		CodeChallenge:       "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_",
		CodeChallengeMethod: client.S256,
		UserID:              testUserID,
		Client: &client.Client{
			Name:          "Test Client",
			Type:          client.Public,
			RequiresPKCE:  true,
			RedirectURIS:  []string{testRedirectURI},
			GrantTypes:    []string{constants.AuthorizationCodeGrantType},
			Scopes:        []string{constants.ClientManageScope},
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
		Type:          client.Confidential,
		RedirectURIS:  []string{testClientID},
		Scopes:        []string{constants.ClientManageScope, constants.UserReadScope},
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
