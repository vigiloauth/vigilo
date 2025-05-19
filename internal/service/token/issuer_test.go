package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

func TestTokenIssuer_IssueTokenPair(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		tokenService    *mocks.MockTokenService
	}{
		{
			name:            "Success",
			wantErr:         false,
			expectedErrCode: "",
			tokenService: &mocks.MockTokenService{
				GenerateAccessTokenWithClaimsFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, tokenType types.TokenType, claims *claims.ClaimsRequest) (string, error) {
					return "token", nil
				},
				GenerateTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, tokenType types.TokenType) (string, error) {
					return "token", nil
				},
			},
		},
		{
			name:            "Internal server error is returned when generating a refresh token",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			tokenService: &mocks.MockTokenService{
				GenerateAccessTokenWithClaimsFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, tokenType types.TokenType, claims *claims.ClaimsRequest) (string, error) {
					return "token", nil
				},
				GenerateTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, tokenType types.TokenType) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:            "Internal server error is returned when generating an access token",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			tokenService: &mocks.MockTokenService{
				GenerateAccessTokenWithClaimsFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, tokenType types.TokenType, claims *claims.ClaimsRequest) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenIssuer(test.tokenService)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			accessToken, refreshToken, err := service.IssueTokenPair(
				ctx,
				"user-1234",
				"client-1234",
				types.OpenIDScope,
				"nonce",
				&claims.ClaimsRequest{},
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error codes to be equal")
				assert.Empty(t, accessToken, "Expected the access token to be empty")
				assert.Empty(t, refreshToken, "Expected the refresh token to be empty")
			} else {
				assert.Nil(t, err, "Expected no error but got: %v", err)
				assert.NotEmpty(t, accessToken, "Expected the access token to not be empty")
				assert.NotEmpty(t, refreshToken, "Expected the refresh token to not be empty")
			}
		})
	}
}
