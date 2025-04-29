package repository

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/constants"
	domain "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
)

const clientID string = "clientID"

func TestInMemoryClientStore_CreateClient(t *testing.T) {
	t.Run("Successful Client Creation", func(t *testing.T) {
		ctx := context.Background()
		cs := NewInMemoryClientRepository()
		client := createTestClient()

		err := cs.SaveClient(ctx, client)
		assert.NoError(t, err, "expected no error when creating client")

		retrievedClient, err := cs.GetClientByID(ctx, clientID)
		assert.NoError(t, err)
		assert.NotNil(t, retrievedClient, "expected retrieved client to not be nil")
		assert.Equal(t, retrievedClient, client, "expected both clients to be equal")
	})

	t.Run("Duplicate entry", func(t *testing.T) {
		ctx := context.Background()
		cs := NewInMemoryClientRepository()
		client := createTestClient()

		// Create first client
		err := cs.SaveClient(ctx, client)
		assert.NoError(t, err, "expected no error when creating client")

		// Attempt to add a duplicate client
		expected := errors.New(errors.ErrCodeDuplicateClient, "client already exists with given ID")
		actual := cs.SaveClient(ctx, client)

		assert.Error(t, actual, "expected error when creating duplicate client")
		assert.Equal(t, actual, expected)
	})
}

func TestInMemoryClientStore_GetClient(t *testing.T) {
	ctx := context.Background()
	cs := NewInMemoryClientRepository()
	client := createTestClient()

	err := cs.SaveClient(ctx, client)
	assert.NoError(t, err, "expected no error when creating client")

	retrievedClient, err := cs.GetClientByID(ctx, clientID)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedClient)
	assert.Equal(t, retrievedClient, client)
}

func TestInMemoryClientStore_DeleteClient(t *testing.T) {
	ctx := context.Background()
	cs := NewInMemoryClientRepository()
	client := createTestClient()

	err := cs.SaveClient(ctx, client)
	assert.NoError(t, err, "expected no error when creating client")

	err = cs.DeleteClientByID(ctx, clientID)
	assert.NoError(t, err, "expected no error when deleting client")

	existingClient, err := cs.GetClientByID(ctx, clientID)
	assert.Error(t, err)
	assert.Nil(t, existingClient, "expected client to be nil")
}

func TestInMemoryClientStore_UpdateClient(t *testing.T) {
	ctx := context.Background()
	t.Run("Successful Client Update", func(t *testing.T) {
		cs := NewInMemoryClientRepository()
		client := createTestClient()

		err := cs.SaveClient(ctx, client)
		assert.NoError(t, err, "expected no error when creating client")

		client.Name = "New Client Name"
		err = cs.UpdateClient(ctx, client)
		assert.NoError(t, err)

		retrievedClient, err := cs.GetClientByID(ctx, clientID)
		assert.NoError(t, err)
		assert.NotNil(t, retrievedClient)
		assert.Equal(t, retrievedClient.Name, client.Name)
	})

	t.Run("Client not found for update", func(t *testing.T) {
		cs := NewInMemoryClientRepository()
		client := createTestClient()

		expected := errors.New(errors.ErrCodeClientNotFound, "client not found using provided ID")
		actual := cs.UpdateClient(ctx, client)
		assert.Equal(t, expected, actual)
	})
}

func createTestClient() *domain.Client {
	now := time.Now()
	return &domain.Client{
		Name:         "Test Client",
		ID:           clientID,
		Secret:       "test-client-secret",
		Type:         domain.Confidential,
		RedirectURIS: []string{"http://localhost:8080/callback"},
		GrantTypes:   []string{constants.AuthorizationCode, constants.RefreshToken},
		Scopes:       []string{constants.ClientRead, constants.ClientWrite},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}
