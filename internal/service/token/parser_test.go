package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/jwt"
)

func TestTokenParser_ParseToken(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		expectedClaims  *token.TokenClaims
		jwtService      *mocks.MockJWTService
	}{
		{
			name:            "Success",
			wantErr:         false,
			expectedErrCode: "",
			expectedClaims:  getTestTokenClaims(),
			jwtService: &mocks.MockJWTService{
				ParseWithClaimsFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
					return getTestTokenClaims(), nil
				},
			},
		},
		{
			name:            "Internal server error is returned when failing to parse claims",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			expectedClaims:  nil,
			jwtService: &mocks.MockJWTService{
				ParseWithClaimsFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
					return nil, errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenParser(test.jwtService)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			claims, err := service.ParseToken(ctx, "token")

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error codes to be equal")
				assert.Nil(t, claims, "Expected claims to be nil")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, claims, "Expected claims to not be nil")
				assert.Equal(t, test.expectedClaims.Scopes, claims.Scopes, "Expected Scopes to be equal")
				assert.Equal(t, test.expectedClaims.Nonce, claims.Nonce, "Expected Nonce values to be equal")
			}
		})
	}
}
