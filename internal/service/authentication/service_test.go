package service

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/common"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	domain "github.com/vigiloauth/vigilo/internal/domain/token"
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
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name         string
			clientSecret string
		}{
			{
				name:         "Successful auth for public client",
				clientSecret: "",
			},
			{
				name:         "Successful auth for confidential client",
				clientSecret: testClientSecret,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				mockClientService := &mClientService.MockClientService{
					AuthenticateClientFunc: func(clientID, clientSecret, requestedGrantType, requestedScopes string) error {
						return nil
					},
				}
				mockTokenService := &mTokenService.MockTokenService{
					GenerateRefreshAndAccessTokensFunc: func(subject, scopes string) (string, string, error) {
						return "refresh", "access", nil
					},
				}

				service := NewAuthenticationService(mockTokenService, mockClientService, nil)
				response, err := service.IssueClientCredentialsToken(testClientID, test.clientSecret, client.ClientCredentials, client.ClientManage)

				assert.NoError(t, err)
				assert.NotNil(t, response)
			})
		}
	})

	t.Run("Error is returned when there is an error generating the refresh token", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
		}
		mockTokenService := &mTokenService.MockTokenService{
			GenerateRefreshAndAccessTokensFunc: func(subject, scopes string) (string, string, error) {
				return "", "", errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, nil)
		response, err := service.IssueClientCredentialsToken(testClientID, testClientSecret, client.ClientCredentials, client.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned authenticating the client", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return errors.New(errors.ErrCodeInvalidClient, "invalid client")
			},
		}

		service := NewAuthenticationService(nil, mockClientService, nil)
		response, err := service.IssueClientCredentialsToken(testClientID, testClientSecret, client.ClientCredentials, client.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestAuthenticationService_IssuePasswordToken(t *testing.T) {
	loginAttempt := &user.UserLoginAttempt{
		Username: testUsername,
		Password: testPassword,
	}

	t.Run("Success", func(t *testing.T) {
		mockUserService := &mUserService.MockUserService{
			GetUserByUsernameFunc: func(username string) *user.User {
				return &user.User{
					ID:       testUserID,
					Username: testUsername,
					Scopes:   []string{client.UserManage},
				}
			},
			HandleOAuthLoginFunc: func(request *user.UserLoginRequest, clientID, redirectURI, remoteAddr, forwardedFor, userAgent string) (*user.UserLoginResponse, error) {
				return &user.UserLoginResponse{}, nil
			},
		}
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
		}
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokensWithAudienceFunc: func(userID, clientID, scopes string) (string, string, error) {
				return "mocked-access-token", "mocked-refresh-token", nil
			},
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, mockUserService)
		response, err := service.IssueResourceOwnerToken(testClientID, testClientSecret, client.PasswordGrant, client.UserManage, loginAttempt)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Error is returned generating tokens", func(t *testing.T) {
		mockUserService := &mUserService.MockUserService{
			GetUserByUsernameFunc: func(username string) *user.User {
				return &user.User{
					ID:       testUserID,
					Username: testUsername,
					Scopes:   []string{client.UserManage},
				}
			},
			HandleOAuthLoginFunc: func(request *user.UserLoginRequest, clientID, redirectURI, remoteAddr, forwardedFor, userAgent string) (*user.UserLoginResponse, error) {
				return &user.UserLoginResponse{}, nil
			},
		}
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
		}
		mockTokenService := &mTokenService.MockTokenService{
			GenerateTokensWithAudienceFunc: func(userID, clientID, scopes string) (string, string, error) {
				return "", "", errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, mockUserService)
		response, err := service.IssueResourceOwnerToken(testClientID, testClientSecret, client.PasswordGrant, client.UserManage, loginAttempt)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned authenticating the client", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return errors.New(errors.ErrCodeInvalidClient, "invalid client")
			},
		}

		service := NewAuthenticationService(nil, mockClientService, nil)
		response, err := service.IssueResourceOwnerToken(testClientID, testClientSecret, client.PasswordGrant, client.UserManage, loginAttempt)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned authenticating the user", func(t *testing.T) {
		mockUserService := &mUserService.MockUserService{
			GetUserByUsernameFunc: func(username string) *user.User {
				return nil
			},
		}
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
		}

		service := NewAuthenticationService(nil, mockClientService, mockUserService)
		response, err := service.IssueResourceOwnerToken(testClientID, testClientSecret, client.PasswordGrant, client.UserManage, loginAttempt)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when the user does not have the required scopes", func(t *testing.T) {
		mockUserService := &mUserService.MockUserService{
			GetUserByUsernameFunc: func(username string) *user.User {
				return &user.User{
					ID:       testUserID,
					Username: testUsername,
					Scopes:   []string{client.UserRead, client.UserDelete},
				}
			},
		}
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, requestedGrantType, requestedScopes string) error {
				return nil
			},
		}

		service := NewAuthenticationService(nil, mockClientService, mockUserService)
		response, err := service.IssueResourceOwnerToken(testClientID, testClientSecret, client.PasswordGrant, client.UserManage, loginAttempt)

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestAuthenticationService_RefreshAccessToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name         string
			clientSecret string
		}{
			{
				name:         "Successful access token refresh for a confidential client",
				clientSecret: testClientSecret,
			},
			{
				name:         "Successful access token refresh for a public client",
				clientSecret: "",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				mockClientService := &mClientService.MockClientService{
					AuthenticateClientFunc: func(clientID, clientSecret, grantType, scopes string) error {
						return nil
					},
				}
				mockTokenService := &mTokenService.MockTokenService{
					ValidateTokenFunc: func(token string) error { return nil },
					GenerateRefreshAndAccessTokensFunc: func(subject, scopes string) (string, string, error) {
						return "refresh-token", "access-token", nil
					},
					ParseTokenFunc: func(token string) (*domain.TokenClaims, error) {
						return &domain.TokenClaims{
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
					BlacklistTokenFunc: func(token string) error { return nil },
				}

				service := NewAuthenticationService(mockTokenService, mockClientService, nil)
				result, err := service.RefreshAccessToken(testClientID, test.clientSecret, client.RefreshToken, testRefreshToken, client.ClientManage)

				assert.NoError(t, err)
				assert.NotNil(t, result)
			})
		}
	})

	t.Run("Invalid client error is returned when client authentication fails", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, grantType, scopes string) error {
				return errors.New(errors.ErrCodeInvalidClient, "failed to authenticate client")
			},
		}

		service := NewAuthenticationService(nil, mockClientService, nil)
		result, err := service.RefreshAccessToken(testClientID, testClientSecret, client.RefreshToken, testRefreshToken, client.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("Invalid grant error is returned on token errors", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, grantType, scopes string) error { return nil },
		}
		mockTokenService := &mTokenService.MockTokenService{
			ValidateTokenFunc: func(token string) error {
				return errors.New(errors.ErrCodeInvalidGrant, "error validating the refresh token")
			},
			BlacklistTokenFunc: func(token string) error { return nil },
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, nil)
		result, err := service.RefreshAccessToken(testClientID, testClientSecret, client.RefreshToken, testRefreshToken, client.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("Unauthorized client error is returned when the client does not have the required grant type", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			AuthenticateClientFunc: func(clientID, clientSecret, grantType, scopes string) error {
				return errors.New(errors.ErrCodeUnauthorizedClient, "client does not have required grant type")
			},
		}
		mockTokenService := &mTokenService.MockTokenService{
			BlacklistTokenFunc: func(token string) error { return nil },
		}

		service := NewAuthenticationService(mockTokenService, mockClientService, nil)
		result, err := service.RefreshAccessToken(testClientID, testClientSecret, client.RefreshToken, testRefreshToken, client.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}

func TestAuthenticationService_IntrospectToken(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(token string) (*domain.TokenData, error) {
				return &domain.TokenData{
					Token:     testRefreshToken,
					ID:        testClientID,
					ExpiresAt: time.Now().Add(10),
					TokenID:   testTokenID,
				}, nil
			},
			ParseTokenFunc: func(token string) (*domain.TokenClaims, error) {
				return &domain.TokenClaims{
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
			IsTokenExpiredFunc:     func(token string) bool { return false },
			IsTokenBlacklistedFunc: func(token string) bool { return false },
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(testRefreshToken)

		assert.NotNil(t, response)
		assert.True(t, response.Active)
	})

	t.Run("Active is set to false when the token does not exist", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(token string) (*domain.TokenData, error) {
				return nil, nil
			},
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(testRefreshToken)

		assert.False(t, response.Active)
	})

	t.Run("Active is set to false when their is an error parsing the token", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(token string) (*domain.TokenData, error) {
				return &domain.TokenData{
					Token:     testRefreshToken,
					ID:        testClientID,
					ExpiresAt: time.Now().Add(10),
					TokenID:   testTokenID,
				}, nil
			},
			ParseTokenFunc: func(token string) (*domain.TokenClaims, error) {
				return nil, errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(testRefreshToken)

		assert.False(t, response.Active)
	})

	t.Run("Active is set to false when the token is expired", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(token string) (*domain.TokenData, error) {
				return &domain.TokenData{
					Token:     testRefreshToken,
					ID:        testClientID,
					ExpiresAt: time.Now().Add(10),
					TokenID:   testTokenID,
				}, nil
			},
			ParseTokenFunc: func(token string) (*domain.TokenClaims, error) {
				return &domain.TokenClaims{
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
			IsTokenExpiredFunc:     func(token string) bool { return true },
			IsTokenBlacklistedFunc: func(token string) bool { return false },
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(testRefreshToken)

		assert.False(t, response.Active)
	})

	t.Run("Active is set to false when the token is blacklisted", func(t *testing.T) {
		mockTokenService := &mTokenService.MockTokenService{
			GetTokenFunc: func(token string) (*domain.TokenData, error) {
				return &domain.TokenData{
					Token:     testRefreshToken,
					ID:        testClientID,
					ExpiresAt: time.Now().Add(10),
					TokenID:   testTokenID,
				}, nil
			},
			ParseTokenFunc: func(token string) (*domain.TokenClaims, error) {
				return &domain.TokenClaims{
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
			IsTokenExpiredFunc:     func(token string) bool { return false },
			IsTokenBlacklistedFunc: func(token string) bool { return true },
		}

		service := NewAuthenticationService(mockTokenService, nil, nil)
		response := service.IntrospectToken(testRefreshToken)

		assert.False(t, response.Active)
	})
}

func TestAuthenticationService_AuthenticateClientRequest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name              string
			requestType       string
			mockClientService *mClientService.MockClientService
			mockTokenService  *mTokenService.MockTokenService
		}{
			{
				name:        "Success when using Basic authorization",
				requestType: common.BasicAuthHeader,
				mockClientService: &mClientService.MockClientService{
					AuthenticateClientFunc: func(clientID, clientSecret, grantType, scopes string) error {
						return nil
					},
				},
				mockTokenService: nil,
			},
			{
				name:        "Success when using Bearer token authorization",
				requestType: common.BearerAuthHeader,
				mockClientService: &mClientService.MockClientService{
					AuthenticateClientFunc: func(clientID, clientSecret, grantType, scopes string) error {
						return nil
					},
				},
				mockTokenService: &mTokenService.MockTokenService{
					ValidateTokenFunc: func(token string) error { return nil },
					ParseTokenFunc: func(token string) (*domain.TokenClaims, error) {
						return &domain.TokenClaims{
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

				if test.requestType == common.BasicAuthHeader {
					req.SetBasicAuth(testClientID, testClientSecret)
				} else {
					req.Header.Set(common.Authorization, common.BearerAuthHeader+bearerToken)
				}

				service := NewAuthenticationService(test.mockTokenService, test.mockClientService, nil)
				err = service.AuthenticateClientRequest(req)
				assert.NoError(t, err)
			})
		}
	})

	t.Run("Error is returned extracting client credentials from basic authorization header", func(t *testing.T) {})

	t.Run("Error is returned authenticating the client", func(t *testing.T) {
		tests := []struct {
			name              string
			requestType       string
			mockClientService *mClientService.MockClientService
			mockTokenService  *mTokenService.MockTokenService
		}{
			{
				name:              "Error is returned authenticating the client using basic authorization",
				requestType:       common.BasicAuthHeader,
				mockClientService: nil,
				mockTokenService:  nil,
			},
			{
				name:              "Error is returned authenticating the client using bearer token authorization",
				requestType:       common.BearerAuthHeader,
				mockClientService: nil,
				mockTokenService:  nil,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {})
		}
	})

	t.Run("Error is returned extracting the bearer token", func(t *testing.T) {})

	t.Run("Error is returned validating the bearer token", func(t *testing.T) {})

	t.Run("Error is returned parsing the bearer token", func(t *testing.T) {})
}
