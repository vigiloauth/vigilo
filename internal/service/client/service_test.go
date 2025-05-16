package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mockClient "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	mockToken "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

const (
	testClientID     string = "client_id"
	testClientSecret string = "client_secret"
	testRedirectURI  string = "http://localhost/callback"
	testToken        string = "test-token"
)

func TestClientService_Register(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}
	mockTokenService := &mockToken.MockTokenService{}
	testClient := createTestClient()
	config.NewServerConfig(config.WithBaseURL(testRedirectURI))
	ctx := context.Background()

	t.Run("Success When Saving Public Client", func(t *testing.T) {
		testClient.Type = types.PublicClient
		mockClientStore.IsExistingIDFunc = func(ctx context.Context, clientID string) bool { return false }
		mockTokenService.GenerateAccessTokenFunc = func(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error) {
			return testToken, nil
		}
		mockClientStore.SaveClientFunc = func(ctx context.Context, client *client.Client) error { return nil }

		cs := NewClientService(mockClientStore, mockTokenService)
		response, err := cs.Register(ctx, testClient)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.NotEqual(t, "", response.RegistrationClientURI)
	})

	t.Run("Error When Generating Client ID", func(t *testing.T) {
		testClient.Type = types.PublicClient
		mockClientStore.IsExistingIDFunc = func(ctx context.Context, clientID string) bool { return true }

		cs := NewClientService(mockClientStore, mockTokenService)
		response, err := cs.Register(ctx, testClient)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Success When Saving Confidential Client", func(t *testing.T) {
		testClient.Type = types.ConfidentialClient
		mockClientStore.IsExistingIDFunc = func(ctx context.Context, clientID string) bool { return false }
		mockClientStore.SaveClientFunc = func(ctx context.Context, client *client.Client) error { return nil }
		mockTokenService.GenerateAccessTokenFunc = func(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error) {
			return testToken, nil
		}

		cs := NewClientService(mockClientStore, mockTokenService)
		response, err := cs.Register(ctx, testClient)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, response.Type, testClient.Type)
	})

	t.Run("Database Error When Saving Client", func(t *testing.T) {
		testClient.Type = types.ConfidentialClient
		mockClientStore.IsExistingIDFunc = func(ctx context.Context, clientID string) bool { return false }
		mockClientStore.SaveClientFunc = func(ctx context.Context, client *client.Client) error {
			return errors.New(errors.ErrCodeDuplicateClient, "client already exists with given ID")
		}

		cs := NewClientService(mockClientStore, mockTokenService)
		response, err := cs.Register(ctx, testClient)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when generating registration access token", func(t *testing.T) {
		testClient.Type = types.ConfidentialClient
		mockClientStore.IsExistingIDFunc = func(ctx context.Context, clientID string) bool { return false }
		mockClientStore.SaveClientFunc = func(ctx context.Context, client *client.Client) error { return nil }
		mockTokenService.GenerateAccessTokenFunc = func(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error) {
			return testToken, nil
		}

		cs := NewClientService(mockClientStore, mockTokenService)
		response, err := cs.Register(ctx, testClient)

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestClientService_AuthenticateClient_CredentialsGrant(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = testClientSecret
		testClient.Type = types.ConfidentialClient
		testClient.ID = testClientID
		testClient.Scopes = append(testClient.Scopes, types.OpenIDScope)
		testClient.GrantTypes = append(testClient.GrantTypes, constants.ClientCredentialsGrantType)

		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}

		cs := NewClientService(mockClientStore, nil)
		err := cs.AuthenticateClient(ctx, testClientID, testClientSecret, constants.ClientCredentialsGrantType, types.OpenIDScope)

		assert.NoError(t, err)
	})

	t.Run("Client Does Not Exist", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return nil, errors.New(errors.ErrCodeClientNotFound, "client not found")
		}

		cs := NewClientService(mockClientStore, nil)
		err := cs.AuthenticateClient(ctx, testClientID, testClientSecret, constants.ClientCredentialsGrantType, types.OpenIDScope)

		assert.Error(t, err)
	})

	t.Run("Client Secrets Do Not Match", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = "client_secret_2"
		testClient.ID = testClientID
		testClient.Scopes = append(testClient.Scopes, types.OpenIDScope)
		testClient.GrantTypes = append(testClient.GrantTypes, constants.ClientCredentialsGrantType)

		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}

		cs := NewClientService(mockClientStore, nil)
		err := cs.AuthenticateClient(ctx, testClientID, testClientSecret, constants.ClientCredentialsGrantType, types.OpenIDScope)

		assert.Error(t, err)
	})

	t.Run("Missing 'client_credentials' Grant Type", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = testClientSecret
		testClient.ID = testClientID
		testClient.Type = types.ConfidentialClient
		testClient.GrantTypes = []string{}
		testClient.Scopes = append(testClient.Scopes, types.OpenIDScope)

		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}

		cs := NewClientService(mockClientStore, nil)
		actual := errors.New(errors.ErrCodeInvalidGrant, "failed to validate client authorization: client does not have the required grant type")
		expected := cs.AuthenticateClient(ctx, testClientID, testClientSecret, constants.ClientCredentialsGrantType, types.OpenIDScope)

		assert.Error(t, expected)
		assert.Equal(t, expected.Error(), actual.Error())
	})
}

func TestClientService_RegenerateClientSecret(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}
	ctx := context.Background()

	t.Run("Successful Client Secret Regeneration", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Type = types.ConfidentialClient
		testClient.ID = testClientID
		testClient.Secret = ""

		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockClientStore.UpdateClientFunc = func(ctx context.Context, client *client.Client) error { return nil }

		cs := NewClientService(mockClientStore, nil)
		response, err := cs.RegenerateClientSecret(ctx, testClientID)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, response.ClientID, testClientID)
		assert.NotEqual(t, response.ClientSecret, testClientSecret)
		assert.NotNil(t, response.UpdatedAt)
	})

	t.Run("Error is returned when 'client_id' is invalid", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return nil, errors.New(errors.ErrCodeInvalidClient, "client does not exist with the given ID")
		}

		cs := NewClientService(mockClientStore, nil)
		expected := errors.New(errors.ErrCodeInvalidClient, "failed to retrieve client: client does not exist with the given ID")
		response, actual := cs.RegenerateClientSecret(ctx, testClientID)

		assert.Error(t, actual)
		assert.Nil(t, response)
		assert.Equal(t, actual.Error(), expected.Error())
	})

	t.Run("Error is returned when client does not have the required scopes", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Secret = testClientSecret
		testClient.Type = types.ConfidentialClient
		testClient.Scopes = []types.Scope{}

		mockClientStore := &mockClient.MockClientRepository{}
		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}

		cs := NewClientService(mockClientStore, nil)
		expected := errors.New(errors.ErrCodeInsufficientScope, "failed to validate client: client does not have the required scope(s)")
		response, actual := cs.RegenerateClientSecret(ctx, testClientID)

		assert.Error(t, actual)
		assert.Nil(t, response)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Error is returned when there is an error updating the client", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Secret = testClientSecret

		mockClientStore := &mockClient.MockClientRepository{}
		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockClientStore.UpdateClientFunc = func(ctx context.Context, client *client.Client) error {
			return errors.New(errors.ErrCodeClientNotFound, "client doest exist with the given ID")
		}

		cs := NewClientService(mockClientStore, nil)
		response, err := cs.RegenerateClientSecret(ctx, testClientID)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when the client is 'public'", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID

		mockClientStore := &mockClient.MockClientRepository{}
		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}

		cs := NewClientService(mockClientStore, nil)
		expected := errors.New(errors.ErrCodeUnauthorizedClient, "invalid credentials")
		response, actual := cs.RegenerateClientSecret(ctx, testClientID)

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
		assert.Nil(t, response)
	})
}

func TestClientService_GetClientByID(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		expected := createTestClient()
		expected.ID = testClientID

		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return expected, nil
		}

		cs := NewClientService(mockClientStore, nil)
		actual, err := cs.GetClientByID(ctx, testClientID)

		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, expected.ID, actual.ID)
		assert.Equal(t, expected.RedirectURIs, actual.RedirectURIs)
	})

	t.Run("Client does not exist with the given ID", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return nil, nil
		}

		cs := NewClientService(mockClientStore, nil)
		response, err := cs.GetClientByID(ctx, testClientID)

		assert.NoError(t, err)
		assert.Nil(t, response)
	})
}

func TestClientService_ValidateAndRetrieveClient(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}
	mockTokenService := &mockToken.MockTokenService{}
	ctx := context.Background()

	t.Run("Success - response does not contain secret for public clients", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = types.PublicClient

		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   testClientID,
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}

		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		cs := NewClientService(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(ctx, testClientID, testToken)

		assert.NoError(t, err)
		assert.NotEqual(t, "", clientInformation.ID)
		assert.Equal(t, "", clientInformation.Secret)
		assert.NotEqual(t, "", clientInformation.RegistrationAccessToken)
		assert.NotEqual(t, "", clientInformation.RegistrationClientURI)
	})

	t.Run("Success - response contains secret for confidential clients", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = types.ConfidentialClient
		testClient.Secret = testClientSecret

		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   testClientID,
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}

		cs := NewClientService(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(ctx, testClientID, testToken)

		assert.NoError(t, err)
		assert.NotEqual(t, "", clientInformation.ID)
		assert.NotEqual(t, "", clientInformation.Secret)
		assert.NotEqual(t, "", clientInformation.RegistrationAccessToken)
		assert.NotEqual(t, "", clientInformation.RegistrationClientURI)
	})

	t.Run("Error is returned when the client does not exist", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return nil, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		cs := NewClientService(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(ctx, testClientID, testToken)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})

	t.Run("Error is returned when the access token is invalid", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = types.ConfidentialClient

		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   "invalid-id",
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		cs := NewClientService(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(ctx, testClientID, testToken)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})

	t.Run("Error is returned when the client ID does not match the access token ID", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = types.ConfidentialClient

		mockClientStore.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   "invalid-id",
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		cs := NewClientService(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(ctx, testClientID, testToken)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})
}

func TestClientService_ValidateAndUpdateClient(t *testing.T) {
	mockClientRepo := &mockClient.MockClientRepository{}
	mockTokenService := &mockToken.MockTokenService{}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockClientRepo.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return createTestClient(), nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   testClientID,
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}
		mockClientRepo.UpdateClientFunc = func(ctx context.Context, client *client.Client) error { return nil }

		service := NewClientService(mockClientRepo, mockTokenService)
		request := createClientUpdateRequest()
		response, err := service.ValidateAndUpdateClient(ctx, testClientID, testToken, request)

		assert.NoError(t, err)
		assert.NotEqual(t, "", response.ID, "ID should not be empty")
		assert.Equal(t, "", response.Secret, "secret should be empty for public client")
		assert.NotEqual(t, "", response.RegistrationAccessToken, "registration access token should not be empty")
		assert.NotEqual(t, "", response.RegistrationClientURI, "registration client URI should not be empty")
	})

	t.Run("Error is returned when the client ID does not match the access token ID", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID

		mockClientRepo.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   "invalid-id",
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		cs := NewClientService(mockClientRepo, mockTokenService)
		request := createClientUpdateRequest()
		clientInformation, err := cs.ValidateAndUpdateClient(ctx, testClientID, testToken, request)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})

	t.Run("Error is returned when the access token is invalid", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = types.ConfidentialClient

		mockClientRepo.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   testClientID,
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		cs := NewClientService(mockClientRepo, mockTokenService)
		clientInformation, err := cs.ValidateAndUpdateClient(ctx, testClientID, testToken, createClientUpdateRequest())

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})

	t.Run("Error is returned when client secrets do not match", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = types.ConfidentialClient
		testClient.Secret = testClientSecret

		mockClientRepo.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   testClientID,
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		cs := NewClientService(mockClientRepo, mockTokenService)
		request := createClientUpdateRequest()
		request.Secret = "invalid-secret"
		clientInformation, err := cs.ValidateAndUpdateClient(ctx, testClientID, testToken, request)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})
}

func TestClientService_ValidateAndDeleteClient(t *testing.T) {
	mockClientRepo := &mockClient.MockClientRepository{}
	mockTokenService := &mockToken.MockTokenService{}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Scopes = append(testClient.Scopes, types.OpenIDScope)

		mockClientRepo.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return createTestClient(), nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   testClientID,
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }
		mockClientRepo.DeleteClientByIDFunc = func(ctx context.Context, clientID string) error { return nil }

		service := NewClientService(mockClientRepo, mockTokenService)
		err := service.ValidateAndDeleteClient(ctx, testClientID, testToken)
		assert.NoError(t, err)
	})

	t.Run("Error - Client ID mismatch", func(t *testing.T) {
		mockClientRepo.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return nil, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		service := NewClientService(mockClientRepo, mockTokenService)
		expectedErrMessage := "the provided client ID is invalid or does not match the registered credentials"
		err := service.ValidateAndDeleteClient(ctx, testClientID, testToken)

		assert.Error(t, err)
		assert.Equal(t, expectedErrMessage, err.Error())
	})

	t.Run("Error - Registration access token and client ID mismatch", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Scopes = append(testClient.Scopes, types.OpenIDScope)
		testClient.ID = testClientID

		mockClientRepo.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   "invalid",
					ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				},
			}, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		service := NewClientService(mockClientRepo, mockTokenService)
		err := service.ValidateAndDeleteClient(ctx, testClientID, testToken)

		assert.Error(t, err)
		assert.Equal(t, "the registration access token subject does not match with the client ID in the request", err.Error())
	})

	t.Run("Error - Registration access token is expired", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Scopes = append(testClient.Scopes, types.OpenIDScope)
		testClient.ID = testClientID

		mockClientRepo.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) {
			return testClient, nil
		}
		mockTokenService.ParseTokenFunc = func(ctx context.Context, token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				StandardClaims: &jwt.StandardClaims{
					Subject:   testClientID,
					ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
				},
			}, nil
		}
		mockTokenService.DeleteTokenFunc = func(ctx context.Context, token string) error { return nil }

		service := NewClientService(mockClientRepo, mockTokenService)
		err := service.ValidateAndDeleteClient(ctx, testClientID, testToken)

		assert.Error(t, err)
		assert.Equal(t, "the registration access token has expired", err.Error())
	})
}

func TestClientService_AuthenticateClient_PasswordGrant(t *testing.T) {
	t.Run("Successful authentication", func(t *testing.T) {
		tests := []struct {
			name           string
			IsConfidential bool
		}{
			{
				name:           "Successful authentication for public client",
				IsConfidential: false,
			},
			{
				name:           "Successful authentication for confidential client",
				IsConfidential: true,
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				req := createTestClient()
				req.GrantTypes = append(req.GrantTypes, constants.PasswordGrantType)

				if test.IsConfidential {
					req.Type = types.ConfidentialClient
					req.Secret = testClientSecret
				}

				mockClientRepo := &mockClient.MockClientRepository{
					GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
						return req, nil
					},
				}

				ctx := context.Background()
				service := NewClientService(mockClientRepo, nil)
				err := service.AuthenticateClient(ctx, req.ID, req.Secret, constants.PasswordGrantType, types.OpenIDScope)
				assert.NoError(t, err, "error is not expected")
			})
		}
	})

	t.Run("Client does not exist", func(t *testing.T) {
		mockClientRepo := &mockClient.MockClientRepository{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return nil, errors.New(errors.ErrCodeInvalidClient, "client credentials are either missing or invalid")
			},
		}

		ctx := context.Background()
		service := NewClientService(mockClientRepo, nil)
		err := service.AuthenticateClient(ctx, testClientID, testClientSecret, constants.PasswordGrantType, types.OpenIDScope)

		assert.Error(t, err)
		assert.Equal(t, "failed to retrieve client: client credentials are either missing or invalid", err.Error())
	})

	t.Run("Client does not have required grant type", func(t *testing.T) {
		req := createTestClient()
		mockClientRepo := &mockClient.MockClientRepository{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return req, nil
			},
		}

		ctx := context.Background()
		service := NewClientService(mockClientRepo, nil)
		err := service.AuthenticateClient(ctx, req.ID, req.Secret, constants.PasswordGrantType, types.OpenIDScope)

		assert.Error(t, err)
		assert.Equal(t, "failed to validate client authorization: client does not have the required grant type", err.Error())
	})

	t.Run("Client secret does not match", func(t *testing.T) {
		req := createTestClient()
		req.Type = types.ConfidentialClient
		req.Secret = testClientSecret

		mockClientRepo := &mockClient.MockClientRepository{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return req, nil
			},
		}

		ctx := context.Background()
		service := NewClientService(mockClientRepo, nil)
		expectedErr := "failed to validate client authorization: the client credentials are invalid or incorrectly formatted"
		err := service.AuthenticateClient(ctx, req.ID, "invalid_secret", constants.PasswordGrantType, types.OpenIDScope)

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err.Error())
	})
}

func createTestClient() *client.Client {
	return &client.Client{
		ID:           testClientID,
		Name:         "Test Name",
		RedirectURIs: []string{testRedirectURI},
		GrantTypes:   []string{constants.AuthorizationCodeGrantType, constants.ClientCredentialsGrantType},
		Scopes:       []types.Scope{types.OpenIDScope},
	}
}

func createClientUpdateRequest() *client.ClientUpdateRequest {
	return &client.ClientUpdateRequest{
		ID:           testClientID,
		Name:         "Test Name",
		RedirectURIs: []string{testRedirectURI},
		GrantTypes:   []string{constants.AuthorizationCodeGrantType, constants.ClientCredentialsGrantType},
		Scopes:       []types.Scope{types.OpenIDScope},
	}
}
