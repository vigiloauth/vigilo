package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/client"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/mocks"
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

func createTestClient() *client.Client {
	return &client.Client{
		Name:         "Test Name",
		RedirectURIS: []string{"https://localhost/callback"},
		GrantTypes:   []client.GrantType{client.AuthorizationCode},
		Scopes:       []client.Scope{client.Read, client.Write},
	}
}
