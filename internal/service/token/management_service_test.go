package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
)

func TestTokenManagementService_Introspect(t *testing.T) {
	tests := []struct {
		name         string
		wantErr      bool
		expected     *token.TokenIntrospectionResponse
		tokenService *mocks.MockTokenService
	}{
		{
			name:     "Success",
			wantErr:  false,
			expected: getTestTokenIntrospectionResponse(),
			tokenService: &mocks.MockTokenService{
				GetTokenDataFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{}, nil
				},
				ParseTokenFunc: func(ctx context.Context, tokenStr string) (*token.TokenClaims, error) {
					return getTestTokenClaims(), nil
				},
				ValidateTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:     "Token is not active when an error occurs retrieving the token data",
			wantErr:  true,
			expected: &token.TokenIntrospectionResponse{Active: false},
			tokenService: &mocks.MockTokenService{
				GetTokenDataFunc: func(ctx context.Context, token string) (*token.TokenData, error) {
					return nil, errors.New(errors.ErrCodeTokenNotFound, "token not found")
				},
			},
		},
		{
			name:     "Token is not active when an error occurs parsing the token string",
			wantErr:  true,
			expected: &token.TokenIntrospectionResponse{Active: false},
			tokenService: &mocks.MockTokenService{
				GetTokenDataFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{}, nil
				},
				ParseTokenFunc: func(ctx context.Context, tokenStr string) (*token.TokenClaims, error) {
					return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
				},
			},
		},
		{
			name:     "Token is not active when it is blacklisted or expired",
			wantErr:  true,
			expected: &token.TokenIntrospectionResponse{Active: false},
			tokenService: &mocks.MockTokenService{
				GetTokenDataFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{}, nil
				},
				ParseTokenFunc: func(ctx context.Context, tokenStr string) (*token.TokenClaims, error) {
					return getTestTokenClaims(), nil
				},
				ValidateTokenFunc: func(ctx context.Context, token string) error {
					return errors.New(errors.ErrCodeExpiredToken, "token is expired")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenManagementService(test.tokenService)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			actual := service.Introspect(ctx, testToken)
			if test.wantErr {
				assert.False(t, actual.Active, "Expected the token to not be active")
			} else {
				assert.True(t, actual.Active, "Expected the token to be active")
				assert.Equal(t, test.expected.ExpiresAt, actual.ExpiresAt, "Expected ExpiresAt values to be equal")
				assert.Equal(t, test.expected.IssuedAt, actual.IssuedAt, "Expected IssuedAt values to be equal")
				assert.Equal(t, test.expected.Subject, actual.Subject, "Expected Subject values to be equal")
				assert.Equal(t, test.expected.Issuer, actual.Issuer, "Expected Issuer values to be the equal")
				assert.Equal(t, test.expected.Audience, actual.Audience, "Expected Audience values to be equal")
			}
		})
	}
}

func TestTokenManagementService_Revoke(t *testing.T) {
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
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:            "Internal server error is returned when blacklisting a token",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			tokenService: &mocks.MockTokenService{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return errors.New(errors.ErrCodeInternalServerError, "token not found")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenManagementService(test.tokenService)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := service.Revoke(ctx, "token")

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error codes to be equal")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}

func getTestTokenIntrospectionResponse() *token.TokenIntrospectionResponse {
	return &token.TokenIntrospectionResponse{
		ExpiresAt: time.Now().Add(15 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Subject:   "user-1234",
		Issuer:    "vigilo",
		Audience:  "client-1234",
	}
}

func getTestTokenClaims() *token.TokenClaims {
	return &token.TokenClaims{
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(15 * time.Hour).Unix(),
			IssuedAt:  time.Now().Unix(),
			Subject:   "user-1234",
			Issuer:    "vigilo",
			Audience:  "client-1234",
		},
	}
}
