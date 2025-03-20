package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/client"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/mocks"
)

const (
	testClientID     string = "client_id"
	testClientSecret string = "client_secret"
)

func TestClientService_SaveClient(t *testing.T) {
	mockClientStore := &mocks.MockClientStore{}
	testClient := createTestClient()

	t.Run("Success When Saving Public Client", func(t *testing.T) {
		testClient.Type = client.Public
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }
		mockClientStore.SaveClientFunc = func(client *client.Client) error { return nil }

		cs := NewClientService(mockClientStore)
		response, err := cs.SaveClient(testClient)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Error When Generating Client ID", func(t *testing.T) {
		testClient.Type = client.Public
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return testClient }

		cs := NewClientService(mockClientStore)
		response, err := cs.SaveClient(testClient)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Success When Saving Confidential Client", func(t *testing.T) {
		testClient.Type = client.Confidential
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }
		mockClientStore.SaveClientFunc = func(client *client.Client) error { return nil }

		cs := NewClientService(mockClientStore)
		response, err := cs.SaveClient(testClient)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, response.Type, testClient.Type)
	})

	t.Run("Database Error When Saving Client", func(t *testing.T) {
		testClient.Type = client.Confidential
		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client { return nil }
		mockClientStore.SaveClientFunc = func(client *client.Client) error {
			return errors.New(errors.ErrCodeDuplicateClient, "client already exists with given ID")
		}

		cs := NewClientService(mockClientStore)
		response, err := cs.SaveClient(testClient)

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestClientService_AuthenticateAndAuthorizeClient(t *testing.T) {
	mockClientStore := &mocks.MockClientStore{}

	t.Run("Success", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = testClientSecret
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
		testClient.Scopes = append(testClient.Scopes, client.ClientManage)
		testClient.GrantTypes = append(testClient.GrantTypes, client.PKCE)

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client {
			return testClient
		}

		cs := NewClientService(mockClientStore)
		actual := errors.New(errors.ErrCodeInvalidGrantType, "client does not have required grant type `client_credentials`")
		result, expected := cs.AuthenticateClientForCredentialsGrant(testClientID, testClientSecret)

		assert.Nil(t, result)
		assert.Error(t, expected)
		assert.Equal(t, expected.Error(), actual.Error())
	})

	t.Run("Missing `client:manage` Scope", func(t *testing.T) {
		testClient := createTestClient()
		testClient.Secret = testClientSecret
		testClient.ID = testClientID
		testClient.GrantTypes = append(testClient.GrantTypes, client.ClientCredentials)

		mockClientStore.GetClientByIDFunc = func(clientID string) *client.Client {
			return testClient
		}

		cs := NewClientService(mockClientStore)
		actual := errors.New(errors.ErrCodeInvalidGrantType, "client does not have required scope `client:manage`")
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

func createTestClient() *client.Client {
	return &client.Client{
		Name:         "Test Name",
		RedirectURIS: []string{"https://localhost/callback"},
		GrantTypes:   []client.GrantType{client.AuthorizationCode},
		Scopes:       []client.Scope{client.ClientRead, client.ClientWrite},
	}
}
