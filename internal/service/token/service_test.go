package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	mTokenRepo "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
)

const (
	testToken        string = "test-token"
	testID           string = "test-id"
	testInvalidToken string = "invalidToken"
	testScopes       string = "clients:read"
	testClientID     string = "client-id"
	testRoles        string = "ADMIN"
)

func TestTokenService_GetToken(t *testing.T) {
	ctx := context.Background()
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		GetTokenFunc: func(ctx context.Context, token string) (*domain.TokenData, error) {
			return &domain.TokenData{
				Token: testToken,
				ID:    testID,
			}, nil
		},
	}

	tokenService := NewTokenService(mockTokenRepo)

	result, err := tokenService.GetTokenData(ctx, testToken)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestTokenService_DeleteToken(t *testing.T) {
	ctx := context.Background()
	mockTokenRepo := &mTokenRepo.MockTokenRepository{
		DeleteTokenFunc: func(ctx context.Context, token string) error {
			return nil
		},
	}

	tokenService := NewTokenService(mockTokenRepo)

	err := tokenService.DeleteToken(ctx, testToken)
	assert.NoError(t, err)
}
