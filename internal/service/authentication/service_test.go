package service

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
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
					GenerateTokenFunc: func(clientID string, duration time.Duration) (string, error) {
						return "mocked-token", nil
					},
				}

				service := NewAuthenticationServiceImpl(mockTokenService, mockClientService, nil)
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
			GenerateTokenFunc: func(clientID string, duration time.Duration) (string, error) {
				return "", errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationServiceImpl(mockTokenService, mockClientService, nil)
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

		service := NewAuthenticationServiceImpl(nil, mockClientService, nil)
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
			GenerateTokenPairFunc: func(userID, clientID string) (string, string, error) {
				return "mocked-access-token", "mocked-refresh-token", nil
			},
		}

		service := NewAuthenticationServiceImpl(mockTokenService, mockClientService, mockUserService)
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
			GenerateTokenPairFunc: func(userID, clientID string) (string, string, error) {
				return "", "", errors.NewInternalServerError()
			},
		}

		service := NewAuthenticationServiceImpl(mockTokenService, mockClientService, mockUserService)
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

		service := NewAuthenticationServiceImpl(nil, mockClientService, nil)
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

		service := NewAuthenticationServiceImpl(nil, mockClientService, mockUserService)
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

		service := NewAuthenticationServiceImpl(nil, mockClientService, mockUserService)
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
					GenerateRefreshAndAccessTokensFunc: func(subject string) (string, string, error) {
						return "refresh-token", "access-token", nil
					},
					ParseTokenFunc: func(token string) (*jwt.StandardClaims, error) {
						return &jwt.StandardClaims{Subject: testClientID}, nil
					},
					BlacklistTokenFunc: func(token string) error { return nil },
				}

				service := NewAuthenticationServiceImpl(mockTokenService, mockClientService, nil)
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

		service := NewAuthenticationServiceImpl(nil, mockClientService, nil)
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

		service := NewAuthenticationServiceImpl(mockTokenService, mockClientService, nil)
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

		service := NewAuthenticationServiceImpl(mockTokenService, mockClientService, nil)
		result, err := service.RefreshAccessToken(testClientID, testClientSecret, client.RefreshToken, testRefreshToken, client.ClientManage)

		assert.Error(t, err)
		assert.Nil(t, result)
	})
}
