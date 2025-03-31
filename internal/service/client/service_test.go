package service

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
	mockClient "github.com/vigiloauth/vigilo/internal/mocks/client"
	mockToken "github.com/vigiloauth/vigilo/internal/mocks/token"
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

	t.Run("Success When Saving Public Client", func(t *testing.T) {
		testClient.Type = client.Public
		mockClientStore.IsExistingIDFunc = func(clientID string) bool { return false }
		mockTokenService.GenerateTokenFunc = func(id string, duration time.Duration) (string, error) {
			return testToken, nil
		}
		mockClientStore.SaveClientFunc = func(client *client.Client) error { return nil }

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		response, err := cs.Register(testClient)

		t.Log(response.ConfigurationEndpoint)
		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.NotEqual(t, "", response.ConfigurationEndpoint)
	})

	t.Run("Error When Generating Client ID", func(t *testing.T) {
		testClient.Type = client.Public
		mockClientStore.IsExistingIDFunc = func(clientID string) bool { return true }

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		response, err := cs.Register(testClient)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Success When Saving Confidential Client", func(t *testing.T) {
		testClient.Type = client.Confidential
		mockClientStore.IsExistingIDFunc = func(clientID string) bool { return false }
		mockClientStore.SaveClientFunc = func(client *client.Client) error { return nil }
		mockTokenService.GenerateTokenFunc = func(id string, duration time.Duration) (string, error) {
			return testToken, nil
		}

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		response, err := cs.Register(testClient)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, response.Type, testClient.Type)
	})

	t.Run("Database Error When Saving Client", func(t *testing.T) {
		testClient.Type = client.Confidential
		mockClientStore.IsExistingIDFunc = func(clientID string) bool { return false }
		mockClientStore.SaveClientFunc = func(client *client.Client) error {
			return errors.New(errors.ErrCodeDuplicateClient, "client already exists with given ID")
		}

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		response, err := cs.Register(testClient)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when generating registration access token", func(t *testing.T) {
		testClient.Type = client.Confidential
		mockClientStore.IsExistingIDFunc = func(clientID string) bool { return false }
		mockClientStore.SaveClientFunc = func(client *client.Client) error { return nil }
		mockTokenService.GenerateTokenFunc = func(id string, duration time.Duration) (string, error) {
			return "", errors.NewInternalServerError()
		}

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		response, err := cs.Register(testClient)

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestClientService_AuthenticateClientForCredentialsGrant(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}

	t.Run("Success", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = testClientSecret
		testClient.Type = client.Confidential
		testClient.ID = testClientID
		testClient.Scopes = append(testClient.Scopes, client.ClientManage)
		testClient.GrantTypes = append(testClient.GrantTypes, client.ClientCredentials)

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client {
			return testClient
		}

		cs := NewClientServiceImpl(mockClientStore, nil)
		result, err := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	t.Run("Client Does Not Exist", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }

		cs := NewClientServiceImpl(mockClientStore, nil)
		result, expected := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.Nil(t, result)
		assert.Error(t, expected)
	})

	t.Run("Client Secrets Do Not Match", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = "client_secret_2"
		testClient.ID = testClientID
		testClient.Scopes = append(testClient.Scopes, client.ClientManage)
		testClient.GrantTypes = append(testClient.GrantTypes, client.ClientCredentials)

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client {
			return testClient
		}

		cs := NewClientServiceImpl(mockClientStore, nil)
		result, expected := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.Nil(t, result)
		assert.Error(t, expected)
	})

	t.Run("Missing 'client_credentials' Grant Type", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = testClientSecret
		testClient.ID = testClientID
		testClient.Type = client.Confidential
		testClient.Scopes = append(testClient.Scopes, client.ClientManage)
		testClient.GrantTypes = []string{client.PKCE}

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client {
			return testClient
		}

		cs := NewClientServiceImpl(mockClientStore, nil)
		actual := errors.New(errors.ErrCodeInvalidGrant, "failed to validate client: client does not have the required grant type")
		result, expected := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.Nil(t, result)
		assert.Error(t, expected)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Missing required scopes", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = testClientSecret
		testClient.ID = testClientID
		testClient.Type = client.Confidential
		testClient.GrantTypes = append(testClient.GrantTypes, client.ClientCredentials)
		testClient.Scopes = []string{client.ClientRead}

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client {
			return testClient
		}

		cs := NewClientServiceImpl(mockClientStore, nil)
		actual := errors.New(errors.ErrCodeInvalidGrant, "failed to validate client: client does not have the required scope(s)")
		result, expected := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.Nil(t, result)
		assert.Error(t, expected)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Empty Parameters Returns an Error", func(t *testing.T) {
		cs := NewClientServiceImpl(mockClientStore, nil)
		expected := errors.New(errors.ErrCodeEmptyInput, "missing required parameter")
		_, actual := cs.AuthenticateClientForCredentialsGrant("", "")

		assert.Error(t, actual)
		assert.Equal(t, actual.Error(), expected.Error())
	})
}

func TestClientService_RegenerateClientSecret(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}

	t.Run("Successful Client Secret Regeneration", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Type = client.Confidential
		testClient.ID = testClientID
		testClient.Secret = ""

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockClientStore.UpdateClientFunc = func(client *client.Client) error { return nil }

		cs := NewClientServiceImpl(mockClientStore, nil)
		response, err := cs.RegenerateClientSecret(testClientID)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, response.ClientID, testClientID)
		assert.NotEqual(t, response.ClientSecret, testClientSecret)
		assert.NotNil(t, response.UpdatedAt)
	})

	t.Run("Error is returned when 'client_id' is invalid", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }

		cs := NewClientServiceImpl(mockClientStore, nil)
		expected := errors.New(errors.ErrCodeInvalidClient, "client does not exist with the given ID")
		response, actual := cs.RegenerateClientSecret(testClientID)

		assert.Error(t, actual)
		assert.Nil(t, response)
		assert.Equal(t, actual.Error(), expected.Error())
	})

	t.Run("Error is returned when client does not have required scope", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Secret = testClientSecret
		testClient.Type = client.Confidential
		testClient.Scopes = []string{}

		mockClientStore := &mockClient.MockClientRepository{}
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }

		cs := NewClientServiceImpl(mockClientStore, nil)
		expected := errors.New(errors.ErrCodeInsufficientScope, "failed to validate client: client does not have the required scope(s)")
		response, actual := cs.RegenerateClientSecret(testClientID)

		assert.Error(t, actual)
		assert.Nil(t, response)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Error is returned when there is an error updating the client", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Secret = testClientSecret

		mockClientStore := &mockClient.MockClientRepository{}
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockClientStore.UpdateClientFunc = func(client *client.Client) error {
			return errors.New(errors.ErrCodeClientNotFound, "client doest exist with the given ID")
		}

		cs := NewClientServiceImpl(mockClientStore, nil)
		response, err := cs.RegenerateClientSecret(testClientID)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when the client is 'public'", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID

		mockClientStore := &mockClient.MockClientRepository{}
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }

		cs := NewClientServiceImpl(mockClientStore, nil)
		expected := errors.New(errors.ErrCodeUnauthorizedClient, "failed to validate client: client is not confidential")
		response, actual := cs.RegenerateClientSecret(testClientID)

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
		assert.Nil(t, response)
	})
}

func TestClientService_GetClientByID(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}

	t.Run("Success", func(t *testing.T) {
		expected := createTestClient()
		expected.ID = testClientID

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client {
			return expected
		}

		cs := NewClientServiceImpl(mockClientStore, nil)
		actual := cs.GetClientByID(testClientID)

		assert.NotNil(t, actual)
		assert.Equal(t, expected.ID, actual.ID)
		assert.Equal(t, expected.RedirectURIS, actual.RedirectURIS)
	})

	t.Run("Client does not exist with the given ID", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }
		cs := NewClientServiceImpl(mockClientStore, nil)
		response := cs.GetClientByID(testClientID)

		assert.Nil(t, response)
	})
}

func TestClientService_ValidateAndRetrieveClient(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}
	mockTokenService := &mockToken.MockTokenService{}

	t.Run("Success - response does not contain secret for public clients", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = client.Public

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{
				Subject:   testClientID,
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		}
		mockTokenService.DeleteTokenAsyncFunc = func(token string) <-chan error { return nil }

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(testClientID, testToken)

		assert.NoError(t, err)
		assert.NotEqual(t, "", clientInformation.ID)
		assert.Equal(t, "", clientInformation.Secret)
		assert.NotEqual(t, "", clientInformation.RegistrationAccessToken)
		assert.NotEqual(t, "", clientInformation.RegistrationClientURI)
	})

	t.Run("Success - response contains secret for confidential clients", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = client.Confidential
		testClient.Secret = testClientSecret

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{
				Subject:   testClientID,
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		}

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(testClientID, testToken)

		assert.NoError(t, err)
		assert.NotEqual(t, "", clientInformation.ID)
		assert.NotEqual(t, "", clientInformation.Secret)
		assert.NotEqual(t, "", clientInformation.RegistrationAccessToken)
		assert.NotEqual(t, "", clientInformation.RegistrationClientURI)
	})

	t.Run("Error is returned when the client does not exist", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(testClientID, testToken)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})

	t.Run("Error is returned when the access token is invalid", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = client.Confidential

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{}, nil
		}
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(testClientID, testToken)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})

	t.Run("Error is returned when the client ID does not match the access token ID", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = client.Confidential

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{Subject: "invalid-id"}, nil
		}
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		cs := NewClientServiceImpl(mockClientStore, mockTokenService)
		clientInformation, err := cs.ValidateAndRetrieveClient(testClientID, testToken)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})
}

func TestClientService_ValidateAndUpdateClient(t *testing.T) {
	mockClientRepo := &mockClient.MockClientRepository{}
	mockTokenService := &mockToken.MockTokenService{}

	t.Run("Success", func(t *testing.T) {
		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client {
			return createTestClient()
		}
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{
				Subject:   testClientID,
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		}
		mockClientRepo.UpdateClientFunc = func(client *client.Client) error { return nil }

		service := NewClientServiceImpl(mockClientRepo, mockTokenService)
		request := createClientUpdateRequest()
		response, err := service.ValidateAndUpdateClient(testClientID, testToken, request)

		assert.NoError(t, err)
		assert.NotEqual(t, "", response.ID, "ID should not be empty")
		assert.Equal(t, "", response.Secret, "secret should be empty for public client")
		assert.NotEqual(t, "", response.RegistrationAccessToken, "registration access token should not be empty")
		assert.NotEqual(t, "", response.RegistrationClientURI, "registration client URI should not be empty")
	})

	t.Run("Error is returned when client does not have the required scopes", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Scopes = []string{}
		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client {
			return testClient
		}
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		service := NewClientServiceImpl(mockClientRepo, mockTokenService)
		request := createClientUpdateRequest()
		request.Scopes = []string{}
		response, err := service.ValidateAndUpdateClient(testClientID, testToken, request)

		assert.Error(t, err, "error is expected")
		assert.Nil(t, response, "client information response should be nil")
	})

	t.Run("Error is returned when the client ID does not match the access token ID", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID

		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{Subject: "invalid-id"}, nil
		}
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		cs := NewClientServiceImpl(mockClientRepo, mockTokenService)
		request := createClientUpdateRequest()
		clientInformation, err := cs.ValidateAndUpdateClient(testClientID, testToken, request)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})

	t.Run("Error is returned when the access token is invalid", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = client.Confidential

		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{}, nil
		}
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		cs := NewClientServiceImpl(mockClientRepo, mockTokenService)
		clientInformation, err := cs.ValidateAndUpdateClient(testClientID, testToken, createClientUpdateRequest())

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})

	t.Run("Error is returned when client secrets do not match", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = client.Confidential
		testClient.Secret = testClientSecret

		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{}, nil
		}
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		cs := NewClientServiceImpl(mockClientRepo, mockTokenService)
		request := createClientUpdateRequest()
		request.Secret = "invalid-secret"
		clientInformation, err := cs.ValidateAndUpdateClient(testClientID, testToken, request)

		assert.Error(t, err)
		assert.Nil(t, clientInformation)
	})

	t.Run("Error - Registration access token is expired", func(t *testing.T) {})
}

func TestClientService_ValidateAndDeleteClient(t *testing.T) {
	mockClientRepo := &mockClient.MockClientRepository{}
	mockTokenService := &mockToken.MockTokenService{}

	t.Run("Success", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Scopes = append(testClient.Scopes, client.ClientDelete)

		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client {
			return createTestClient()
		}
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{
				Subject:   testClientID,
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			}, nil
		}
		mockClientRepo.DeleteClientByIDFunc = func(clientID string) error { return nil }

		service := NewClientServiceImpl(mockClientRepo, mockTokenService)
		err := service.ValidateAndDeleteClient(testClientID, testToken)
		assert.NoError(t, err)
	})

	t.Run("Error - Client ID mismatch", func(t *testing.T) {
		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client { return nil }
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		service := NewClientServiceImpl(mockClientRepo, mockTokenService)
		err := service.ValidateAndDeleteClient(testClientID, testToken)

		assert.Error(t, err)
		assert.Equal(t, "the provided client ID is invalid", err.Error())
	})

	t.Run("Error - Registration access token and client ID mismatch", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Scopes = append(testClient.Scopes, client.ClientDelete)
		testClient.ID = testClientID

		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{Subject: "invalid"}, nil
		}
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		service := NewClientServiceImpl(mockClientRepo, mockTokenService)
		err := service.ValidateAndDeleteClient(testClientID, testToken)

		assert.Error(t, err)
		assert.Equal(t, "the registration access token subject does not match with the client ID in the request", err.Error())
	})

	t.Run("Error - Insufficient scopes", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Scopes = []string{}
		testClient.ID = testClientID

		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		service := NewClientServiceImpl(mockClientRepo, mockTokenService)
		err := service.ValidateAndDeleteClient(testClientID, testToken)

		assert.Error(t, err)
		assert.Equal(t, "client does not have the required scopes for this request", err.Error())
	})

	t.Run("Error - Registration access token is expired", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Scopes = append(testClient.Scopes, client.ClientDelete)
		testClient.ID = testClientID

		mockClientRepo.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockTokenService.ParseTokenFunc = func(token string) (*jwt.StandardClaims, error) {
			return &jwt.StandardClaims{
				Subject:   testClientID,
				ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
			}, nil
		}
		mockTokenService.DeleteTokenFunc = func(token string) error { return nil }

		service := NewClientServiceImpl(mockClientRepo, mockTokenService)
		err := service.ValidateAndDeleteClient(testClientID, testToken)

		assert.Error(t, err)
		assert.Equal(t, "the registration access token has expired", err.Error())
	})
}

func createTestClient() *client.Client {
	return &client.Client{
		ID:           testClientID,
		Name:         "Test Name",
		RedirectURIS: []string{testRedirectURI},
		GrantTypes:   []string{client.AuthorizationCode, client.ClientCredentials},
		Scopes:       []string{client.ClientRead, client.ClientWrite, client.ClientManage},
	}
}

func createClientUpdateRequest() *client.ClientUpdateRequest {
	return &client.ClientUpdateRequest{
		ID:           testClientID,
		Name:         "Test Name",
		RedirectURIS: []string{testRedirectURI},
		GrantTypes:   []string{client.AuthorizationCode, client.ClientCredentials},
		Scopes:       []string{client.ClientRead, client.ClientWrite, client.ClientManage},
	}
}
