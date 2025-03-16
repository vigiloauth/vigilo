package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/client"
	"github.com/vigiloauth/vigilo/internal/mocks"
)

func TestClientService_RegisterPublicClient(t *testing.T) {
	mockClientStore := &mocks.MockClientStore{}
	testClient := createPublicTestClient()

	mockClientStore.GetClientFunc = func(clientID string) *client.Client { return nil }
	mockClientStore.CreateClientFunc = func(client *client.Client) error { return nil }

	cs := NewClientService(mockClientStore)
	response, err := cs.CreatePublicClient(testClient)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.NotNil(t, response)
	assert.NotNil(t, response.CreatedAt)
}

func TestClientService_RegisterPublicClient_ErrorWhenGeneratingClientID(t *testing.T) {
	mockClientStore := &mocks.MockClientStore{}
	testClient := createPublicTestClient()

	mockClientStore.GetClientFunc = func(clientID string) *client.Client { return testClient }

	cs := NewClientService(mockClientStore)
	response, err := cs.CreatePublicClient(testClient)

	assert.Error(t, err)
	assert.Nil(t, response)
}

func createPublicTestClient() *client.Client {
	return &client.Client{
		Name:         "Test Name",
		Type:         client.Public,
		RedirectURIS: []string{"https://localhost/callback"},
		GrantTypes:   []client.GrantType{client.AuthorizationCode},
		Scopes:       []client.Scope{client.Read, client.Write},
	}
}
