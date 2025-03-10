package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	token string = "test-token"
	email string = "email@example.com"
)

func TestTokenStore_AddToken(t *testing.T) {
	tokenStore := GetInMemoryTokenStore()
	expiration := time.Now().Add(1 * time.Hour)

	tokenStore.AddToken(token, email, expiration)

	tokenStore.mu.Lock()
	defer tokenStore.mu.Unlock()
	assert.Contains(t, tokenStore.tokens, token)
}

func TestTokenStore_IsTokenBlacklisted(t *testing.T) {
	tokenStore := GetInMemoryTokenStore()
	expiration := time.Now().Add(1 * time.Hour)

	tokenStore.AddToken(token, email, expiration)
	isBlacklisted := tokenStore.IsTokenBlacklisted(token)

	assert.True(t, isBlacklisted)
}

func TestTokenStore_TokenExpires(t *testing.T) {
	tokenStore := GetInMemoryTokenStore()
	expiration := time.Now().Add(-1 * time.Hour) // Token already expired

	tokenStore.AddToken(token, email, expiration)
	isBlacklisted := tokenStore.IsTokenBlacklisted(token)

	assert.False(t, isBlacklisted)
	tokenStore.mu.Lock()
	defer tokenStore.mu.Unlock()
	assert.NotContains(t, tokenStore.tokens, token)
}

func TestTokenStore_DeleteToken(t *testing.T) {
	tokenStore := GetInMemoryTokenStore()
	expiration := time.Now().Add(1 * time.Hour)

	tokenStore.AddToken(token, email, expiration)
	_, err := tokenStore.GetToken(token, email)
	assert.NoError(t, err)

	err = tokenStore.DeleteToken(token)
	assert.NoError(t, err)

	retrievedToken, err := tokenStore.GetToken(token, email)
	assert.Error(t, err)
	assert.Nil(t, retrievedToken)
}
