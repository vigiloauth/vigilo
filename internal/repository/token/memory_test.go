package repository

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/identity/config"
)

const (
	testToken string = "test-token"
	testID    string = "test-id"
)

func setup() {
	config.GetServerConfig().Logger().SetLevel("DEBUG")
}

func tearDown() {
	config.GetServerConfig().Logger().SetLevel("INFO")
}

func TestTokenStore_AddToken(t *testing.T) {
	setup()
	defer tearDown()

	tokenStore := GetInMemoryTokenRepository()
	expiration := time.Now().Add(1 * time.Hour)

	tokenStore.SaveToken(testToken, testID, expiration)

	tokenStore.mu.Lock()
	defer tokenStore.mu.Unlock()
	assert.Contains(t, tokenStore.tokens, testToken)
}

func TestTokenStore_IsTokenBlacklisted(t *testing.T) {
	setup()
	defer tearDown()

	tokenStore := GetInMemoryTokenRepository()
	expiration := time.Now().Add(-1 * time.Hour)

	tokenStore.SaveToken(testToken, testID, expiration)
	isBlacklisted := tokenStore.IsTokenBlacklisted(testToken)

	assert.True(t, isBlacklisted)
}

func TestTokenStore_DeleteToken(t *testing.T) {
	setup()
	defer tearDown()

	tokenStore := GetInMemoryTokenRepository()
	expiration := time.Now().Add(1 * time.Hour)

	tokenStore.SaveToken(testToken, testID, expiration)
	_, err := tokenStore.GetToken(testToken, testID)
	assert.NoError(t, err)

	err = tokenStore.DeleteToken(testToken)
	assert.NoError(t, err)

	retrievedToken, err := tokenStore.GetToken(testToken, testID)
	assert.Error(t, err)
	assert.Nil(t, retrievedToken)
}
