package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
	mockClient "github.com/vigiloauth/vigilo/internal/mocks/client"
)

const (
	testClientID     string = "client_id"
	testClientSecret string = "client_secret"
	testRedirectURI  string = "http://localhost/callback"
)

func TestClientService_Register(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}
	testClient := createTestClient()

	t.Run("Success When Saving Public Client", func(t *testing.T) {
		testClient.Type = client.Public
		mockClientStore.IsExistingIDFunc = func(clientID string) bool { return false }
		mockClientStore.SaveClientFunc = func(client *client.Client) error { return nil }

		cs := NewClientService(mockClientStore)
		response, err := cs.Register(testClient)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Error When Generating Client ID", func(t *testing.T) {
		testClient.Type = client.Public
		mockClientStore.IsExistingIDFunc = func(clientID string) bool { return true }

		cs := NewClientService(mockClientStore)
		response, err := cs.Register(testClient)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Success When Saving Confidential Client", func(t *testing.T) {
		testClient.Type = client.Confidential
		mockClientStore.IsExistingIDFunc = func(clientID string) bool { return false }
		mockClientStore.SaveClientFunc = func(client *client.Client) error { return nil }

		cs := NewClientService(mockClientStore)
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

		cs := NewClientService(mockClientStore)
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

		cs := NewClientService(mockClientStore)
		result, err := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.NotNil(t, result)
		assert.NoError(t, err)
	})

	t.Run("Client Does Not Exist", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }

		cs := NewClientService(mockClientStore)
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

		cs := NewClientService(mockClientStore)
		result, expected := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.Nil(t, result)
		assert.Error(t, expected)
	})

	t.Run("Missing `client_credentials` Grant Type", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = testClientSecret
		testClient.ID = testClientID
		testClient.Type = client.Confidential
		testClient.Scopes = append(testClient.Scopes, client.ClientManage)
		testClient.GrantTypes = []string{client.PKCE}

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client {
			return testClient
		}

		cs := NewClientService(mockClientStore)
		actual := errors.New(errors.ErrCodeInvalidGrant, "failed to validate client: client does not have required grant type")
		result, expected := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.Nil(t, result)
		assert.Error(t, expected)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Missing `client:manage` Scope", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = testClientSecret
		testClient.ID = testClientID
		testClient.Type = client.Confidential
		testClient.GrantTypes = append(testClient.GrantTypes, client.ClientCredentials)
		testClient.Scopes = []string{client.ClientRead}

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client {
			return testClient
		}

		cs := NewClientService(mockClientStore)
		actual := errors.New(errors.ErrCodeInvalidGrant, "failed to validate client: client does not have required scope")
		result, expected := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.Nil(t, result)
		assert.Error(t, expected)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Empty Parameters Returns an Error", func(t *testing.T) {
		cs := NewClientService(mockClientStore)
		expected := errors.New(errors.ErrCodeEmptyInput, "missing required parameter")
		_, actual := cs.AuthenticateClientForCredentialsGrant("", "")

		assert.Error(t, actual)
		assert.Equal(t, actual.Error(), expected.Error())
	})
}

func TestClientService_RegenerateClientSecret(t *testing.T) {
	t.Run("Successful Client Secret Regeneration", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Type = client.Confidential
		testClient.ID = testClientID
		testClient.Secret = ""

		mockClientStore := &mockClient.MockClientRepository{}
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }
		mockClientStore.UpdateClientFunc = func(client *client.Client) error { return nil }

		cs := NewClientService(mockClientStore)
		response, err := cs.RegenerateClientSecret(testClientID)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, response.ClientID, testClientID)
		assert.NotEqual(t, response.ClientSecret, testClientSecret)
		assert.NotNil(t, response.UpdatedAt)
	})

	t.Run("Error is returned when 'client_id' is invalid", func(t *testing.T) {
		mockClientStore := &mockClient.MockClientRepository{}
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }

		cs := NewClientService(mockClientStore)
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

		cs := NewClientService(mockClientStore)
		expected := errors.New(errors.ErrCodeInvalidScope, "failed to validate client: invalid 'client_secret' provided")
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

		cs := NewClientService(mockClientStore)
		response, err := cs.RegenerateClientSecret(testClientID)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when the client is 'public'", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID

		mockClientStore := &mockClient.MockClientRepository{}
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }

		cs := NewClientService(mockClientStore)
		expected := errors.New(errors.ErrCodeUnauthorizedClient, "failed to validate client: client is not type 'confidential'")
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

		cs := NewClientService(mockClientStore)
		actual := cs.GetClientByID(testClientID)

		assert.NotNil(t, actual)
		assert.Equal(t, expected.ID, actual.ID)
		assert.Equal(t, expected.RedirectURIS, actual.RedirectURIS)
	})

	t.Run("Client does not exist with the given ID", func(t *testing.T) {
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }
		cs := NewClientService(mockClientStore)
		response := cs.GetClientByID(testClientID)

		assert.Nil(t, response)
	})
}

func TestClientService_ValidateClientRedirectURI(t *testing.T) {
	mockClientStore := &mockClient.MockClientRepository{}

	t.Run("Success", func(t *testing.T) {
		testClient := createTestClient()
		testClient.ID = testClientID
		testClient.Type = client.Public

		cs := NewClientService(mockClientStore)
		err := cs.ValidateClientRedirectURI(testRedirectURI, testClient)

		assert.NoError(t, err)
	})

	t.Run("Error is returned when parameters are empty", func(t *testing.T) {
		expectedMessage := "one or more parameters are empty"
		cs := NewClientService(mockClientStore)
		err := cs.ValidateClientRedirectURI("", nil)

		assert.Error(t, err)
		assert.Contains(t, expectedMessage, err.Error())
	})

	t.Run("Error is returned when redirectURIs do not match", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Type = client.Public
		invalidRedirectURI := "https://localhost/callback/2"

		cs := NewClientService(mockClientStore)
		err := cs.ValidateClientRedirectURI(invalidRedirectURI, testClient)

		assert.Error(t, err)
	})

	t.Run("Error is returned when given an invalid redirect URI", func(t *testing.T) {
		testClient := createTestClient()
		invalidRedirectURI := "https/invalid/callback"

		cs := NewClientService(mockClientStore)
		err := cs.ValidateClientRedirectURI(invalidRedirectURI, testClient)

		assert.Error(t, err)
	})
}

func createTestClient() *client.Client {
	return &client.Client{
		Name:         "Test Name",
		RedirectURIS: []string{testRedirectURI},
		GrantTypes:   []string{client.AuthorizationCode, client.ClientCredentials},
		Scopes:       []string{client.ClientRead, client.ClientWrite, client.ClientManage},
	}
}
