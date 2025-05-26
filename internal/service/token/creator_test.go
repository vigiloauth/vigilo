package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/crypto"
	jwtMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/jwt"
	mockRepo "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

func TestTokenCreator_CreateAccessToken(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
		repo    *mockRepo.MockTokenRepository
		jwt     *jwtMocks.MockJWTService
		crypto  *mocks.MockCryptographer
	}{
		{
			name: "Success",
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
		},
		{
			name:    "Error is returned when storing the token",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return errors.NewInternalServerError()
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
		},
		{
			name:    "Error is returned when the token exists by ID",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return true, nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
		},
		{
			name:    "Error is returned when signing the token",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenCreator(test.repo, test.jwt, test.crypto)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			accessToken, err := service.CreateAccessToken(
				ctx,
				"subject",
				"audience",
				types.OpenIDScope,
				constants.AdminRole,
				"nonce",
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Empty(t, accessToken, "Expected the access token to be empty")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotEmpty(t, accessToken, "Expected the access token to not be empty")
			}
		})
	}
}

func TestTokenCreator_CreateRefreshToken(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
		repo    *mockRepo.MockTokenRepository
		jwt     *jwtMocks.MockJWTService
		crypto  *mocks.MockCryptographer
	}{
		{
			name: "Success",
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
		},
		{
			name:    "Error is returned when storing the token",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return errors.NewInternalServerError()
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
		},
		{
			name:    "Error is returned when the token exists by ID",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return true, nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
		},
		{
			name:    "Error is returned when signing the token",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenCreator(test.repo, test.jwt, test.crypto)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			refreshToken, err := service.CreateRefreshToken(
				ctx,
				"subject",
				"audience",
				types.OpenIDScope,
				constants.AdminRole,
				"nonce",
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Empty(t, refreshToken, "Expected the refresh token to be empty")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotEmpty(t, refreshToken, "Expected the refresh token to not be empty")
			}
		})
	}
}

func TestTokenCreator_CreateAccessTokenWithClaims(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
		repo    *mockRepo.MockTokenRepository
		jwt     *jwtMocks.MockJWTService
		crypto  *mocks.MockCryptographer
	}{
		{
			name: "Success",
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
		},
		{
			name:    "Error is returned when storing the token",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return errors.NewInternalServerError()
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
		},
		{
			name:    "Error is returned when the token exists by ID",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return true, nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
		},
		{
			name:    "Error is returned when signing the token",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenCreator(test.repo, test.jwt, test.crypto)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			accessToken, err := service.CreateAccessTokenWithClaims(
				ctx,
				"subject",
				"audience",
				types.OpenIDScope,
				constants.AdminRole,
				"nonce",
				&domain.ClaimsRequest{
					UserInfo: &domain.ClaimSet{
						"name": &domain.ClaimSpec{
							Essential: true,
						},
					},
				},
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Empty(t, accessToken, "Expected the access token to be empty")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotEmpty(t, accessToken, "Expected the access token to not be empty")
			}
		})
	}
}

func TestTokenCreator_CreateIDToken(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
		repo    *mockRepo.MockTokenRepository
		jwt     *jwtMocks.MockJWTService
		crypto  *mocks.MockCryptographer
	}{
		{
			name: "Success",
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
		},
		{
			name:    "Error is returned when storing the token",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return errors.NewInternalServerError()
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
		},
		{
			name:    "Error is returned when the token exists by ID",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return true, nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "signed-token", nil
				},
			},
		},
		{
			name:    "Error is returned when signing the token",
			wantErr: true,
			repo: &mockRepo.MockTokenRepository{
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
			},
			jwt: &jwtMocks.MockJWTService{
				SignTokenFunc: func(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenCreator(test.repo, test.jwt, test.crypto)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			IDToken, err := service.CreateIDToken(
				ctx,
				"userID",
				"clientID",
				types.OpenIDScope,
				"nonce",
				"1 2",
				time.Now(),
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Empty(t, IDToken, "Expected the ID token to be empty")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotEmpty(t, IDToken, "Expected the ID token to not be empty")
			}
		})
	}
}
