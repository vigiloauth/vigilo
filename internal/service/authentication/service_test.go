package service

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/constants"
	clients "github.com/vigiloauth/vigilo/internal/domain/client"
	tokens "github.com/vigiloauth/vigilo/internal/domain/token"

	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	mClientService "github.com/vigiloauth/vigilo/internal/mocks/client"
	mTokenService "github.com/vigiloauth/vigilo/internal/mocks/token"
	mUserService "github.com/vigiloauth/vigilo/internal/mocks/user"
)

const (
	testClientID     string = "test-client-id"
	testClientSecret string = "test-client-secret"
	testUsername     string = "test-username"
	testPassword     string = "test-password"
	testUserID       string = "test-user-id"
	testRefreshToken string = "valid-refresh-token"
	testTokenID      string = "test-token-id"
	testURL          string = "https://localhost.com"
	bearerToken      string = "bearer-token"
)

func TestAuthenticationService_IssueClientCredentialsToken(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name         string
			clientSecret string
			clientType   string
		}{
			{
				name:         "Successful auth for public client",
				clientSecret: "",
				clientType:   clients.Public,
			},
			{
				name:         "Successful auth for confidential client",
				clientSecret: testClientSecret,
				clientType:   clients.Confidential,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				mockClientService := &mClientService.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string) error {
						return nil
					},
					GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
						return &clients.Client{
							Secret: test.clientSecret,
							Type:   test.clientType,
						}, nil
					},
				}
				mockTokenService := &mTokenService.MockTokenService{
					GenerateRefreshAndAccessTokensFunc: func(ctx context.Context, subject, scopes, roles string) (string, string, error) {
						return "refresh", "access", nil
					},
					EncryptTokenFunc: func(ctx context.Context, signedToken string) (string, error) {
						return "access", nil
					},
				}

				service := NewAuthenticationService(mockTokenService, mockClientService, nil)
				response, err := service.IssueClientCredentialsToken(ctx, testClientID, test.clientSecret, constants.ClientCredentials, constants.ClientManage)

				assert.NoError(t, err)
				assert.NotNil(t, response)
			})
		}
	})

	t.Run("Error is returned when there is an error generating the refresh token", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
				return &clients.Client{ID: clientID}, nil
			},
		}
		mockTokenService := &mTokenService.MockTokenService{
			GenerateRefreshAndAccessTokensFunc: func(ctx context.Context, subject, scopes, roles string) (string, string, error) {
				return "", "", errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, nil)
		response, err := service.IssueClientCredentialsToken(ctx, testClientID, testClientSecret, constants.ClientCredentials, constants.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned authenticating the client", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return errors.New(errors.ErrCodeInvalidClient, "invalid client")
			},
		}

		service := NewAuthenticationService(nil, mockClientService, nil)
		response, err := service.IssueClientCredentialsToken(ctx, testClientID, testClientSecret, constants.ClientCredentials, constants.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestAuthenticationService_IssuePasswordToken(t *testing.T) {
	loginAttempt := &user.UserLoginAttempt{
		Username: testUsername,
		Password: testPassword,
	}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockUserService := &mUserService.MockUserService{
			GetUserByUsernameFunc: func(ctx context.Context, username string) (*user.User, error) {
				return &user.User{
					ID:       testUserID,
					Username: testUsername,
					Scopes:   []string{constants.UserManage},
				}, nil
			},
			HandleOAuthLoginFunc: func(ctx context.Context, request *user.UserLoginRequest, clientID, redirectURI string) (*user.UserLoginResponse, error) {
				return &user.UserLoginResponse{}, nil
			},
		}
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
				return &clients.Client{ID: clientID}, nil
			},
		}
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokensWithAudienceFunc: func(ctx context.Context, userID, clientID, scopes, roles string) (string, string, error) {
				return "mocked-access-token", "mocked-refresh-token", nil
			},
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, mockUserService)
		response, err := service.IssueResourceOwnerToken(ctx, testClientID, testClientSecret, constants.PasswordGrant, constants.UserManage, loginAttempt)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Error is returned generating tokens", func(t *testing.T) {
		mockUserService := &mUserService.MockUserService{
			GetUserByUsernameFunc: func(ctx context.Context, username string) (*user.User, error) {
				return &user.User{
					ID:       testUserID,
					Username: testUsername,
					Scopes:   []string{constants.UserManage},
				}, nil
			},
			HandleOAuthLoginFunc: func(ctx context.Context, request *user.UserLoginRequest, clientID, redirectURI string) (*user.UserLoginResponse, error) {
				return &user.UserLoginResponse{}, nil
			},
		}
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
		}
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokensWithAudienceFunc: func(ctx context.Context, userID, clientID, scopes, roles string) (string, string, error) {
				return "", "", errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, mockUserService)
		response, err := service.IssueResourceOwnerToken(ctx, testClientID, testClientSecret, constants.PasswordGrant, constants.UserManage, loginAttempt)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned authenticating the client", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return errors.New(errors.ErrCodeInvalidClient, "invalid client")
			},
		}

		service := NewAuthenticationService(nil, mockClientService, nil)
		response, err := service.IssueResourceOwnerToken(ctx, testClientID, testClientSecret, constants.PasswordGrant, constants.UserManage, loginAttempt)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned authenticating the user", func(t *testing.T) {
		mockUserService := &mUserService.MockUserService{
			GetUserByUsernameFunc: func(ctx context.Context, username string) (*user.User, error) {
				return nil, nil
			},
		}
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
		}

		service := NewAuthenticationService(nil, mockClientService, mockUserService)
		response, err := service.IssueResourceOwnerToken(ctx, testClientID, testClientSecret, constants.PasswordGrant, constants.UserManage, loginAttempt)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when the user does not have the required scopes", func(t *testing.T) {
		mockUserService := &mUserService.MockUserService{
			GetUserByUsernameFunc: func(ctx context.Context, username string) (*user.User, error) {
				return &user.User{
					ID:       testUserID,
					Username: testUsername,
					Scopes:   []string{constants.UserRead, constants.UserDelete},
				}, nil
			},
		}
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
		}

		service := NewAuthenticationService(nil, mockClientService, mockUserService)
		response, err := service.IssueResourceOwnerToken(ctx, testClientID, testClientSecret, constants.PasswordGrant, constants.UserManage, loginAttempt)

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestAuthenticationService_RefreshAccessToken(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name         string
			clientSecret string
			clientType   string
		}{
			{
				name:         "Successful access token refresh for a confidential client",
				clientSecret: testClientSecret,
				clientType:   clients.Confidential,
			},
			{
				name:         "Successful access token refresh for a public client",
				clientSecret: "",
				clientType:   clients.Public,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				mockClientService := &mClientService.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType, scopes string) error {
						return nil
					},
					GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
						return &clients.Client{ID: testClientID, Type: test.clientType, Secret: test.clientSecret}, nil
					},
				}
				mockTokenService := &mTokenService.MockTokenService{
					ValidateTokenFunc: func(ctx context.Context, token string) error { return nil },
					GenerateRefreshAndAccessTokensFunc: func(ctx context.Context, subject, scopes, roles string) (string, string, error) {
						return "refresh-token", "access-token", nil
					},
					ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
						return &tokens.TokenClaims{
							StandardClaims: &jwt.StandardClaims{
								ExpiresAt: time.Now().Add(10).Unix(),
								IssuedAt:  time.Now().Unix(),
								Subject:   testClientID,
								Issuer:    "test-issuer",
								Id:        testTokenID,
								Audience:  "testAudience",
							},
						}, nil
					},
					EncryptTokenFunc: func(ctx context.Context, signedToken string) (string, error) {
						return "token", nil
					},
					BlacklistTokenFunc: func(ctx context.Context, token string) error { return nil },
				}

				service := NewAuthenticationService(mockTokenService, mockClientService, nil)
				result, err := service.RefreshAccessToken(ctx, testClientID, test.clientSecret, constants.RefreshToken, testRefreshToken, constants.ClientManage)

				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("Invalid client error is returned when client authentication fails", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType, scopes string) error {
				return errors.New(errors.ErrCodeInvalidClient, "failed to authenticate client")
			},
		}

		service := NewAuthenticationService(nil, mockClientService, nil)
		result, err := service.RefreshAccessToken(ctx, testClientID, testClientSecret, constants.RefreshToken, testRefreshToken, constants.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("Invalid grant error is returned on token errors", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType, scopes string) error { return nil },
		}
		mockTokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(ctx context.Context, token string) error {
				return errors.New(errors.ErrCodeInvalidGrant, "error validating the refresh token")
			},
			BlacklistTokenFunc: func(ctx context.Context, token string) error { return nil },
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, nil)
		result, err := service.RefreshAccessToken(ctx, testClientID, testClientSecret, constants.RefreshToken, testRefreshToken, constants.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("Unauthorized client error is returned when the client does not have the required grant type", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType, scopes string) error {
				return errors.New(errors.ErrCodeUnauthorizedClient, "client does not have required grant type")
			},
		}
		mockTokenService := &mTokenService.MockTokenService{
			BlacklistTokenFunc: func(ctx context.Context, token string) error { return nil },
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, nil)
		result, err := service.RefreshAccessToken(ctx, testClientID, testClientSecret, constants.RefreshToken, testRefreshToken, constants.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestAuthenticationService_IntrospectToken(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
				return &tokens.TokenData{
					Token:     testRefreshToken,
					ID:        testClientID,
					ExpiresAt: time.Now().Add(10),
					TokenID:   testTokenID,
				}, nil
			},
			ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
				return &tokens.TokenClaims{
					StandardClaims: &jwt.StandardClaims{
						ExpiresAt: time.Now().Add(10).Unix(),
						IssuedAt:  time.Now().Unix(),
						Subject:   testClientID,
						Issuer:    "test-issuer",
						Id:        testTokenID,
						Audience:  "testAudience",
					},
				}, nil
			},
			IsTokenExpiredFunc: func(token string) bool { return false },
			IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
				return false, nil
			},
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(ctx, testRefreshToken)

		assert.NotNil(t, response)
		assert.True(t, response.Active)
	})

	t.Run("Active is set to false when the token does not exist", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
				return nil, nil
			},
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(ctx, testRefreshToken)

		assert.False(t, response.Active)
	})

	t.Run("Active is set to false when their is an error parsing the token", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
				return &tokens.TokenData{
					Token:     testRefreshToken,
					ID:        testClientID,
					ExpiresAt: time.Now().Add(10),
					TokenID:   testTokenID,
				}, nil
			},
			ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
				return nil, errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(ctx, testRefreshToken)

		assert.False(t, response.Active)
	})

	t.Run("Active is set to false when the token is expired", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
				return &tokens.TokenData{
					Token:     testRefreshToken,
					ID:        testClientID,
					ExpiresAt: time.Now().Add(10),
					TokenID:   testTokenID,
				}, nil
			},
			ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
				return &tokens.TokenClaims{
					StandardClaims: &jwt.StandardClaims{
						ExpiresAt: time.Now().Add(10).Unix(),
						IssuedAt:  time.Now().Unix(),
						Subject:   testClientID,
						Issuer:    "test-issuer",
						Id:        testTokenID,
						Audience:  "testAudience",
					},
				}, nil
			},
			IsTokenExpiredFunc: func(token string) bool { return true },
			IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
				return false, nil
			},
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(ctx, testRefreshToken)

		assert.False(t, response.Active)
	})

	t.Run("Active is set to false when the token is blacklisted", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
				return &tokens.TokenData{
					Token:     testRefreshToken,
					ID:        testClientID,
					ExpiresAt: time.Now().Add(10),
					TokenID:   testTokenID,
				}, nil
			},
			ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
				return &tokens.TokenClaims{
					StandardClaims: &jwt.StandardClaims{
						ExpiresAt: time.Now().Add(10).Unix(),
						IssuedAt:  time.Now().Unix(),
						Subject:   testClientID,
						Issuer:    "test-issuer",
						Id:        testTokenID,
						Audience:  "testAudience",
					},
				}, nil
			},
			IsTokenExpiredFunc: func(token string) bool { return false },
			IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
				return true, nil
			},
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(ctx, testRefreshToken)

		assert.False(t, response.Active)
	})
}

func TestAuthenticationService_AuthenticateClientRequest(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name              string
			requestType       string
			mockClientService *mClientService.MockClientService
			mockTokenService  *mTokenService.MockTokenService
		}{
			{
				name:        "Success when using Basic authorization",
				requestType: constants.BasicAuthHeader,
				mockClientService: &mClientService.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType, scopes string) error {
						return nil
					},
				},
				mockTokenService: nil,
			},
			{
				name:        "Success when using Bearer token authorization",
				requestType: constants.BearerAuthHeader,
				mockClientService: &mClientService.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType, scopes string) error {
						return nil
					},
				},
				mockTokenService: &mTokenService.MockTokenService{
					ValidateTokenFunc: func(ctx context.Context, token string) error { return nil },
					ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
						return &tokens.TokenClaims{
							StandardClaims: &jwt.StandardClaims{
								Subject: testClientID,
							},
						}, nil
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, testURL, nil)
				assert.NoError(t, err)

				if test.requestType == constants.BasicAuthHeader {
					req.SetBasicAuth(testClientID, testClientSecret)
				} else {
					req.Header.Set(constants.AuthorizationHeader, constants.BearerAuthHeader+bearerToken)
				}

				service := NewAuthenticationService(test.mockTokenService, test.mockClientService, nil)
				err = service.AuthenticateClientRequest(ctx, req, constants.TokenIntrospect)
				assert.NoError(t, err)
			})
		}
	})

	t.Run("Error is returned extracting client credentials from basic authorization header", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, testURL, nil)
		assert.NoError(t, err)
		req.Header.Set(constants.AuthorizationHeader, constants.BasicAuthHeader+testClientID)

		service := NewAuthenticationService(nil, nil, nil)
		err = service.AuthenticateClientRequest(ctx, req, constants.TokenIntrospect)

		assert.Error(t, err)
	})

	t.Run("Error is returned authenticating the client", func(t *testing.T) {
		tests := []struct {
			name              string
			requestType       string
			mockClientService *mClientService.MockClientService
			mockTokenService  *mTokenService.MockTokenService
		}{
			{
				name:        "Error is returned authenticating the client using basic authorization",
				requestType: constants.BasicAuthHeader,
				mockClientService: &mClientService.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType, scopes string) error {
						return errors.New(errors.ErrCodeInvalidClient, "error message")
					},
				},
				mockTokenService: nil,
			},
			{
				name:        "Error is returned authenticating the client using bearer token authorization",
				requestType: constants.BearerAuthHeader,
				mockClientService: &mClientService.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType, scopes string) error {
						return errors.New(errors.ErrCodeInvalidClient, "error message")
					},
				},
				mockTokenService: &mTokenService.MockTokenService{
					ValidateTokenFunc: func(ctx context.Context, token string) error { return nil },
					ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
						return &tokens.TokenClaims{
							StandardClaims: &jwt.StandardClaims{
								Subject: testClientID,
							},
						}, nil
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, testURL, nil)
				assert.NoError(t, err)

				if test.requestType == constants.BasicAuthHeader {
					req.SetBasicAuth(testClientID, testClientSecret)
				} else {
					req.Header.Set(constants.AuthorizationHeader, constants.BearerAuthHeader+testRefreshToken)
				}

				service := NewAuthenticationService(test.mockTokenService, test.mockClientService, nil)
				err = service.AuthenticateClientRequest(ctx, req, constants.TokenIntrospect)

				assert.Error(t, err)
			})
		}
	})

	t.Run("Error is returned extracting the bearer token", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, testURL, nil)
		assert.NoError(t, err)

		service := NewAuthenticationService(nil, nil, nil)
		err = service.AuthenticateClientRequest(ctx, req, constants.TokenIntrospect)

		assert.Error(t, err)
	})

	t.Run("Error is returned validating the bearer token", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, testURL, nil)
		assert.NoError(t, err)
		req.Header.Set(constants.AuthorizationHeader, constants.BearerAuthHeader+testRefreshToken)

		mockTokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(ctx context.Context, token string) error {
				return errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		err = service.AuthenticateClientRequest(ctx, req, constants.TokenIntrospect)

		assert.Error(t, err)
	})

	t.Run("Error is returned parsing the bearer token", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, testURL, nil)
		assert.NoError(t, err)
		req.Header.Set(constants.AuthorizationHeader, constants.BearerAuthHeader+testRefreshToken)

		mockTokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(ctx context.Context, token string) error {
				return nil
			},
			ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
				return nil, errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		err = service.AuthenticateClientRequest(ctx, req, constants.TokenIntrospect)

		assert.Error(t, err)
	})
}

func TestAuthenticationService_RevokeToken(t *testing.T) {
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		tokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
				return &tokens.TokenData{}, nil
			},
			ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
				return &tokens.TokenClaims{}, nil
			},
			BlacklistTokenFunc: func(ctx context.Context, token string) error {
				return nil
			},
			IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
				return true, nil
			},
		}

		service := NewAuthenticationService(tokenService, nil, nil)
		service.RevokeToken(ctx, testRefreshToken)

		isBlacklisted, err := tokenService.IsTokenBlacklistedFunc(ctx, testRefreshToken)
		assert.NoError(t, err)
		assert.True(t, isBlacklisted)
	})

	t.Run("Errors", func(t *testing.T) {
		tests := []struct {
			name         string
			tokenService *mTokenService.MockTokenService
		}{
			{
				name: "Error while retrieving the token",
				tokenService: &mTokenService.MockTokenService{
					GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
						return nil, nil
					},
					BlacklistTokenFunc: func(ctx context.Context, token string) error { return nil },
				},
			},
			{
				name: "Error while parsing the token",
				tokenService: &mTokenService.MockTokenService{
					GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
						return &tokens.TokenData{}, nil
					},
					ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
						return nil, errors.NewInternalServerError()
					},
					BlacklistTokenFunc: func(ctx context.Context, token string) error { return nil },
				},
			},
			{
				name: "Error while adding the token to the blacklist",
				tokenService: &mTokenService.MockTokenService{
					GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
						return &tokens.TokenData{}, nil
					},
					ParseAndValidateTokenFunc: func(ctx context.Context, token string) (*tokens.TokenClaims, error) {
						return &tokens.TokenClaims{}, nil
					},
					BlacklistTokenFunc: func(ctx context.Context, token string) error {
						return errors.NewInternalServerError()
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				service := NewAuthenticationService(test.tokenService, nil, nil)
				service.RevokeToken(ctx, testRefreshToken)
			})
		}
	})
}
