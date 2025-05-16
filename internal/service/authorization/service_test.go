package service

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mAuthzCodeService "github.com/vigiloauth/vigilo/v2/internal/mocks/authzcode"
	mClientService "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	mSessionService "github.com/vigiloauth/vigilo/v2/internal/mocks/session"
	mTokenService "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	mUser "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
	mConsentService "github.com/vigiloauth/vigilo/v2/internal/mocks/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/web"
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
	testRequestID       string = "req-1234"
	testState           string = "state12345"
	testNonce           string = "nonce12345"
)

func TestAuthorizationService_AuthorizeClient(t *testing.T) {
	tests := []struct {
		name             string
		wantErr          bool
		request          *client.ClientAuthorizationRequest
		consentService   *mConsentService.MockUserConsentService
		clientService    *mClientService.MockClientService
		sessionService   *mSessionService.MockSessionService
		authzCodeService *mAuthzCodeService.MockAuthorizationCodeService
		expectedURL      string
	}{
		{
			name:    "Invalid client ID",
			wantErr: true,
			request: &client.ClientAuthorizationRequest{ClientID: "invalidID"},
			clientService: &mClientService.MockClientService{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return nil, errors.New(errors.ErrCodeClientNotFound, "client not found by ID")
				},
			},
		},
		{
			name:    "Prompt login forces redirect",
			wantErr: false,
			request: &client.ClientAuthorizationRequest{
				ClientID:     testClientID,
				RedirectURI:  testRedirectURI,
				Scope:        constants.OpenIDScope,
				ResponseType: constants.CodeResponseType,
				State:        testState,
				Nonce:        testNonce,
				Prompt:       constants.PromptLogin,
				Display:      constants.DisplayPage,
			},
			clientService: &mClientService.MockClientService{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{ID: testClientID}, nil
				},
			},
			expectedURL: web.BuildRedirectURL(
				testClientID,
				testRedirectURI,
				constants.OpenIDScope,
				constants.CodeResponseType,
				testState,
				testNonce,
				constants.PromptLogin,
				constants.DisplayPage,
				"authenticate",
			),
		},
		{
			name:    "Prompt is set to none and user is not authenticated returns errorURL",
			wantErr: false,
			clientService: &mClientService.MockClientService{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{ID: clientID}, nil
				},
			},
			sessionService: &mSessionService.MockSessionService{
				GetUserIDFromSessionFunc: func(r *http.Request) (string, error) {
					return "", errors.New(errors.ErrCodeSessionNotFound, "user session not found")
				},
			},
			request: &client.ClientAuthorizationRequest{
				State:       testState,
				RedirectURI: testRedirectURI,
				Prompt:      constants.PromptNone,
			},
			expectedURL: web.BuildErrorURL(errors.ErrCodeLoginRequired, "authentication required to continue", testState, testRedirectURI),
		},
		{
			name:    "Prompt is set to none and no previous consent",
			wantErr: false,
			request: &client.ClientAuthorizationRequest{
				State:       testState,
				RedirectURI: testRedirectURI,
				Prompt:      constants.PromptNone,
			},
			clientService: &mClientService.MockClientService{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{ID: clientID}, nil
				},
			},
			sessionService: &mSessionService.MockSessionService{
				GetUserIDFromSessionFunc: func(r *http.Request) (string, error) {
					return testUserID, nil
				},
			},
			consentService: &mConsentService.MockUserConsentService{
				CheckUserConsentFunc: func(ctx context.Context, userID, clientID, scope string) (bool, error) {
					return false, nil
				},
			},
			expectedURL: web.BuildErrorURL(errors.ErrCodeInteractionRequired, "user consent is required to continue", testState, testRedirectURI),
		},
		{
			name:    "Validation fails",
			wantErr: true,
			request: &client.ClientAuthorizationRequest{
				RedirectURI: "invalid redirect URI",
			},
			clientService: &mClientService.MockClientService{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{ID: clientID}, nil
				},
			},
			sessionService: &mSessionService.MockSessionService{
				GetUserIDFromSessionFunc: func(r *http.Request) (string, error) {
					return testUserID, nil
				},
			},
		},
		{
			name:    "Consent URL return when consent is required",
			wantErr: false,
			request: &client.ClientAuthorizationRequest{
				ClientID:     testClientID,
				RedirectURI:  testRedirectURI,
				Scope:        constants.OpenIDScope,
				ResponseType: constants.CodeResponseType,
				State:        testState,
				Nonce:        testNonce,
			},
			expectedURL: web.BuildRedirectURL(
				testClientID,
				testRedirectURI,
				constants.OpenIDScope,
				constants.CodeResponseType,
				testState,
				testNonce,
				"", "", "consent",
			),
			clientService: &mClientService.MockClientService{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:            clientID,
						ResponseTypes: []string{constants.CodeResponseType},
						GrantTypes:    []string{constants.AuthorizationCodeGrantType}}, nil
				},
			},
			sessionService: &mSessionService.MockSessionService{
				GetUserIDFromSessionFunc: func(r *http.Request) (string, error) {
					return testUserID, nil
				},
			},
			consentService: &mConsentService.MockUserConsentService{
				CheckUserConsentFunc: func(ctx context.Context, userID, clientID, scope string) (bool, error) {
					return false, nil
				},
			},
		},
		{
			name:    "Error is returned when generating authorization code",
			wantErr: true,
			request: &client.ClientAuthorizationRequest{
				ClientID:     testClientID,
				RedirectURI:  testRedirectURI,
				Scope:        constants.OpenIDScope,
				ResponseType: constants.CodeResponseType,
				State:        testState,
				Nonce:        testNonce,
				Display:      constants.DisplayPage,
			},
			clientService: &mClientService.MockClientService{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:            clientID,
						ResponseTypes: []string{constants.CodeResponseType},
						GrantTypes:    []string{constants.AuthorizationCodeGrantType}}, nil
				},
			},
			sessionService: &mSessionService.MockSessionService{
				GetUserIDFromSessionFunc: func(r *http.Request) (string, error) {
					return testUserID, nil
				},
			},
			consentService: &mConsentService.MockUserConsentService{
				CheckUserConsentFunc: func(ctx context.Context, userID, clientID, scope string) (bool, error) {
					return true, nil
				},
			},
			authzCodeService: &mAuthzCodeService.MockAuthorizationCodeService{
				GenerateAuthorizationCodeFunc: func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
					return "", errors.New(errors.ErrCodeInternalServerError, "failed to generate authorization code")
				},
			},
		},
		{
			name:    "Authentication URL is returned when user is not authenticated",
			wantErr: false,
			request: &client.ClientAuthorizationRequest{
				ClientID:     testClientID,
				RedirectURI:  testRedirectURI,
				Scope:        constants.OpenIDScope,
				ResponseType: constants.CodeResponseType,
				State:        testState,
				Nonce:        testNonce,
				Display:      constants.DisplayPage,
			},
			clientService: &mClientService.MockClientService{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{ID: clientID}, nil
				},
			},
			sessionService: &mSessionService.MockSessionService{
				GetUserIDFromSessionFunc: func(r *http.Request) (string, error) {
					return "", nil
				},
			},
			expectedURL: web.BuildRedirectURL(
				testClientID,
				testRedirectURI,
				constants.OpenIDScope,
				constants.CodeResponseType,
				testState,
				testNonce,
				"", "",
				"authenticate",
			),
		},
		{
			name: "Success",
			request: &client.ClientAuthorizationRequest{
				ClientID:     testClientID,
				RedirectURI:  testRedirectURI,
				Scope:        constants.OpenIDScope,
				ResponseType: constants.CodeResponseType,
				State:        testState,
				Nonce:        testNonce,
				Display:      constants.DisplayPage,
				UserID:       testUserID,
			},
			clientService: &mClientService.MockClientService{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:            clientID,
						ResponseTypes: []string{constants.CodeResponseType},
						GrantTypes:    []string{constants.AuthorizationCodeGrantType}}, nil
				},
			},
			sessionService: &mSessionService.MockSessionService{
				GetUserIDFromSessionFunc: func(r *http.Request) (string, error) {
					return testUserID, nil
				},
			},
			consentService: &mConsentService.MockUserConsentService{
				CheckUserConsentFunc: func(ctx context.Context, userID, clientID, scope string) (bool, error) {
					return true, nil
				},
			},
			authzCodeService: &mAuthzCodeService.MockAuthorizationCodeService{
				GenerateAuthorizationCodeFunc: func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
					return testAuthzCode, nil
				},
			},
			expectedURL: fmt.Sprintf("%s?code=%s&nonce=%s&state=%s", testRedirectURI, testAuthzCode, testNonce, testState),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)
			service := NewAuthorizationService(
				test.authzCodeService,
				test.consentService,
				nil, test.clientService,
				nil, test.sessionService,
			)

			redirectURL, err := service.AuthorizeClient(ctx, test.request)
			if test.wantErr {
				assert.Error(t, err, "Expected an error")
				assert.Empty(t, redirectURL, "Expected the redirect URL to be empty")
			} else {
				assert.NoError(t, err, "Expected no error")
				assert.NotEmpty(t, redirectURL, "Expected the redirect URL to not be empty")
				assert.Equal(t, redirectURL, test.expectedURL)
			}
		})
	}
}

func TestAuthorizationService_AuthorizeTokenExchange(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
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
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				data := getTestAuthzCodeData()
				data.Used = true
				return data, nil
			},
		}

		service := NewAuthorizationService(mockAuthzCodeService, nil, nil, nil, nil, nil)
		expected := "authorization code already used"
		actual, err := service.AuthorizeTokenExchange(ctx, getTestTokenRequest())

		assert.Error(t, err)
		assert.Equal(t, expected, err.Error())
		assert.Nil(t, actual)
	})

	t.Run("Error is returned validating client", func(t *testing.T) {
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
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
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				return getTestAuthzCodeData(), nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
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
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				data := getTestAuthzCodeData()
				data.CodeChallenge = "code-challenge"
				return data, nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
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
			GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
				data := getTestAuthzCodeData()
				data.CodeChallenge = "code-challenge"
				return data, nil
			},
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
			ValidatePKCEFunc: func(authzCodeData *authzCode.AuthorizationCodeData, codeVerifier string) error {
				return errors.New(errors.ErrCodeInvalidGrant, "PKCE validation failed")
			},
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
			GenerateAccessTokenFunc: func(ctx context.Context, subject, audience, scopes, roles, nonce string) (string, error) {
				return "accessToken", nil
			},
			GenerateRefreshTokenFunc: func(ctx context.Context, subject, audience, scopes, roles, nonce string) (string, error) {
				return "refreshToken", nil
			},
			GenerateIDTokenFunc: func(ctx context.Context, userID, clientID, scopes, nonce string, authTime time.Time) (string, error) {
				return "idToken", nil
			},
		}
		mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{
			UpdateAuthorizationCodeFunc: func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
				return nil
			},
		}

		service := NewAuthorizationService(mockAuthzCodeService, nil, mockTokenService, mockClientService, nil, nil)

		actual, err := service.GenerateTokens(ctx, getTestAuthzCodeData())

		assert.NoError(t, err)
		assert.NotNil(t, actual)
	})

	t.Run("Error is returned generating access token", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GenerateAccessTokenFunc: func(ctx context.Context, subject, audience, scopes, roles, nonce string) (string, error) {
				return "", errors.NewInternalServerError()
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
