package repository

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

const clientID string = "clientID"

func TestInMemoryClientStore_CreateClient(t *testing.T) {
	t.Run("Successful Client Creation", func(t *testing.T) {
		ctx := context.Background()
		cs := NewInMemoryClientRepository()
		client := createTestClient()

		err := cs.SaveClient(ctx, client)
		require.NoError(t, err, "expected no error when creating client")

		retrievedClient, err := cs.GetClientByID(ctx, clientID)
		require.NoError(t, err)
		assert.NotNil(t, retrievedClient, "expected retrieved client to not be nil")
		assert.Equal(t, retrievedClient, client, "expected both clients to be equal")
	})

	t.Run("Duplicate entry", func(t *testing.T) {
		ctx := context.Background()
		cs := NewInMemoryClientRepository()
		client := createTestClient()

		// Create first client
		err := cs.SaveClient(ctx, client)
		require.NoError(t, err, "expected no error when creating client")

		// Attempt to add a duplicate client
		expected := errors.New(errors.ErrCodeDuplicateClient, "client already exists with given ID")
		actual := cs.SaveClient(ctx, client)

		require.Error(t, actual, "expected error when creating duplicate client")
		assert.Equal(t, expected, actual)
	})
}

func TestInMemoryClientStore_GetClient(t *testing.T) {
	ctx := context.Background()
	cs := NewInMemoryClientRepository()
	client := createTestClient()

	err := cs.SaveClient(ctx, client)
	require.NoError(t, err, "expected no error when creating client")

	retrievedClient, err := cs.GetClientByID(ctx, clientID)
	require.NoError(t, err)
	assert.NotNil(t, retrievedClient)
	assert.Equal(t, retrievedClient, client)
}

func TestInMemoryClientStore_DeleteClient(t *testing.T) {
	ctx := context.Background()
	cs := NewInMemoryClientRepository()
	client := createTestClient()

	err := cs.SaveClient(ctx, client)
	require.NoError(t, err, "expected no error when creating client")

	err = cs.DeleteClientByID(ctx, clientID)
	require.NoError(t, err, "expected no error when deleting client")

	existingClient, err := cs.GetClientByID(ctx, clientID)
	require.Error(t, err)
	assert.Nil(t, existingClient, "expected client to be nil")
}

func TestInMemoryClientStore_UpdateClient(t *testing.T) {
	ctx := context.Background()
	t.Run("Successful Client Update", func(t *testing.T) {
		cs := NewInMemoryClientRepository()
		client := createTestClient()

		err := cs.SaveClient(ctx, client)
		require.NoError(t, err, "expected no error when creating client")

		client.Name = "New Client Name"
		err = cs.UpdateClient(ctx, client)
		require.NoError(t, err)

		retrievedClient, err := cs.GetClientByID(ctx, clientID)
		require.NoError(t, err)
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
		Type:         types.ConfidentialClient,
		RedirectURIs: []string{"http://localhost:8080/callback"},
		GrantTypes:   []string{constants.AuthorizationCodeGrantType, constants.RefreshTokenGrantType},
		Scopes:       []types.Scope{types.OpenIDScope},
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}
