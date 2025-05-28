package repository

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

const (
	testToken string = "test-token"
	testID    string = "test-id"
)

func TestTokenStore_AddToken(t *testing.T) {
	tokenStore := GetInMemoryTokenRepository()
	expiration := time.Now().Add(1 * time.Hour)

	_ = tokenStore.SaveToken(context.Background(), testToken, testID, &domain.TokenData{}, expiration)

	tokenStore.mu.Lock()
	defer tokenStore.mu.Unlock()
	assert.Contains(t, tokenStore.tokens, testToken)
}

func TestTokenStore_IsTokenBlacklisted(t *testing.T) {
	ctx := context.Background()
	tokenStore := GetInMemoryTokenRepository()
	expiration := time.Now().Add(-1 * time.Hour)

	tokenData := &domain.TokenData{
		TokenClaims: &domain.TokenClaims{
			StandardClaims: &jwt.StandardClaims{
				ExpiresAt: expiration.Unix(),
			},
		},
	}

	_ = tokenStore.SaveToken(ctx, testToken, testID, tokenData, expiration)
	isBlacklisted, err := tokenStore.IsTokenBlacklisted(ctx, testToken)

	assert.NoError(t, err)
	assert.True(t, isBlacklisted)
}

func TestTokenStore_DeleteToken(t *testing.T) {
	ctx := context.Background()
	tokenStore := GetInMemoryTokenRepository()
	expiration := time.Now().Add(1 * time.Hour)

	err := tokenStore.SaveToken(ctx, testToken, testID, &domain.TokenData{}, expiration)
	assert.NoError(t, err)

	token, err := tokenStore.GetToken(ctx, testToken)
	assert.NoError(t, err)
	assert.NotNil(t, token)

	err = tokenStore.DeleteToken(ctx, testToken)
	assert.NoError(t, err)

	retrievedToken, err := tokenStore.GetToken(ctx, testToken)
	assert.Error(t, err)
	assert.Nil(t, retrievedToken)
}
