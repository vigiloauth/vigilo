package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
)

func TestTokenValidator_ValidateToken(t *testing.T) {
	requestID := "req-1234"

	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		repo            *mocks.MockTokenRepository
		parser          *mocks.MockTokenParser
	}{
		{
			name:            "Success",
			wantErr:         false,
			expectedErrCode: "",
			repo: &mocks.MockTokenRepository{
				IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
					return false, nil
				},
			},
			parser: &mocks.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return getTestTokenClaims(), nil
				},
			},
		},
		{
			name:            "Error while parsing token should return expired token error code",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeExpiredToken],
			repo:            nil,
			parser: &mocks.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return nil, errors.NewInternalServerError("")
				},
			},
		},
		{
			name:            "Expired Token error code is returned when the token is expired",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeExpiredToken],
			repo:            nil,
			parser: &mocks.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return &tokens.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							ExpiresAt: time.Now().Add(-15 * time.Hour).Unix(),
						},
					}, nil
				},
			},
		},
		{
			name:            "Unauthorized error is returned when the token is blacklisted",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			repo: &mocks.MockTokenRepository{
				IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
					return true, nil
				},
			},
			parser: &mocks.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return getTestTokenClaims(), nil
				},
			},
		},
		{
			name:            "Unauthorized error is returned when the a DB error occurs",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			repo: &mocks.MockTokenRepository{
				IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
					return true, errors.NewInternalServerError("")
				},
			},
			parser: &mocks.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return getTestTokenClaims(), nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenValidator(test.repo, test.parser)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			err := service.ValidateToken(ctx, "token")

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error codes to be equal")
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}
