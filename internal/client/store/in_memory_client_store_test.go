package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/client"
	"github.com/vigiloauth/vigilo/internal/errors"
)

const clientID string = "clientID"

func TestInMemoryClientStore_CreateClient(t *testing.T) {
	t.Run("Successful Client Creation", func(t *testing.T) {
		cs := NewInMemoryClientStore()
		client := createTestClient()

		err := cs.CreateClient(client)
		assert.NoError(t, err, "expected no error when creating client")

		retrievedClient := cs.GetClient(clientID)
		assert.NotNil(t, retrievedClient, "expected retrieved client to not be nil")
		assert.Equal(t, retrievedClient, client, "expected both clients to be equal")
	})

	t.Run("Duplicate entry", func(t *testing.T) {
		cs := NewInMemoryClientStore()
		client := createTestClient()

		// Create first client
		err := cs.CreateClient(client)
		assert.NoError(t, err, "expected no error when creating client")

		// Attempt to add a duplicate client
		expected := errors.New(errors.ErrCodeDuplicateClient, "client already exists with given ID")
		actual := cs.CreateClient(client)

		assert.Error(t, actual, "expected error when creating duplicate client")
		assert.Equal(t, actual, expected)
	})
}

func TestInMemoryClientStore_GetClient(t *testing.T) {
	cs := NewInMemoryClientStore()
	client := createTestClient()

	err := cs.CreateClient(client)
	assert.NoError(t, err, "expected no error when creating client")

	retrievedClient := cs.GetClient(clientID)
	assert.NotNil(t, retrievedClient)
	assert.Equal(t, retrievedClient, client)
}

func TestInMemoryClientStore_DeleteClient(t *testing.T) {
	cs := NewInMemoryClientStore()
	client := createTestClient()

	err := cs.CreateClient(client)
	assert.NoError(t, err, "expected no error when creating client")

	err = cs.DeleteClient(clientID)
	assert.NoError(t, err, "expected no error when deleting client")

	existingClient := cs.GetClient(clientID)
	assert.Nil(t, existingClient, "expected client to be nil")
}

func TestInMemoryClientStore_UpdateClient(t *testing.T) {
	t.Run("Successful Client Update", func(t *testing.T) {
		cs := NewInMemoryClientStore()
		client := createTestClient()

		err := cs.CreateClient(client)
		assert.NoError(t, err, "expected no error when creating client")

		client.Name = "New Client Name"
		err = cs.UpdateClient(client)
		assert.NoError(t, err)

		retrievedClient := cs.GetClient(clientID)
		assert.NotNil(t, retrievedClient)
		assert.Equal(t, retrievedClient.Name, client.Name)
	})

	t.Run("Client not found for update", func(t *testing.T) {
		cs := NewInMemoryClientStore()
		client := createTestClient()

		expected := errors.New(errors.ErrCodeClientNotFound, "client not found using provided ID")
		actual := cs.UpdateClient(client)
		assert.Equal(t, expected, actual)
	})
}

func createTestClient() *client.Client {
	now := time.Now()
	return &client.Client{
		Name:         "Test Client",
		ID:           clientID,
		Secret:       "test-client-secret",
		Type:         client.Confidential,
		RedirectURIS: []string{"http://localhost:8080/callback"},
		GrantTypes:   []client.GrantType{client.AuthorizationCode, client.RefreshToken},
		Scopes:       []client.Scope{client.Read, client.Write},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}
