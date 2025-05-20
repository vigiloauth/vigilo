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

func TestTokenManager_Introspect(t *testing.T) {
	tests := []struct {
		name      string
		wantErr   bool
		expected  *token.TokenIntrospectionResponse
		repo      *mocks.MockTokenRepository
		parser    *mocks.MockTokenParser
		validator *mocks.MockTokenValidator
	}{
		{
			name:     "Success",
			wantErr:  false,
			expected: getTestTokenIntrospectionResponse(),
			repo: &mocks.MockTokenRepository{
				GetTokenFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{}, nil
				},
			},
			parser: &mocks.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
					return getTestTokenClaims(), nil
				},
			},
			validator: &mocks.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
		},
		{
			name:     "Token is not active when an error occurs retrieving the token data",
			wantErr:  true,
			expected: &token.TokenIntrospectionResponse{Active: false},
			repo: &mocks.MockTokenRepository{
				GetTokenFunc: func(ctx context.Context, token string) (*token.TokenData, error) {
					return nil, errors.New(errors.ErrCodeTokenNotFound, "token not found")
				},
			},
		},
		{
			name:     "Token is not active when an error occurs parsing the token string",
			wantErr:  true,
			expected: &token.TokenIntrospectionResponse{Active: false},
			repo: &mocks.MockTokenRepository{
				GetTokenFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{}, nil
				},
			},
			parser: &mocks.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
					return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
				},
			},
			validator: nil,
		},
		{
			name:     "Token is not active when it is blacklisted or expired",
			wantErr:  true,
			expected: &token.TokenIntrospectionResponse{Active: false},
			repo: &mocks.MockTokenRepository{
				GetTokenFunc: func(ctx context.Context, tokenStr string) (*token.TokenData, error) {
					return &token.TokenData{}, nil
				},
			},
			parser: &mocks.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenStr string) (*token.TokenClaims, error) {
					return getTestTokenClaims(), nil
				},
			},
			validator: &mocks.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, token string) error {
					return errors.New(errors.ErrCodeExpiredToken, "token is expired")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenManager(test.repo, test.parser, test.validator)
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

func TestTokenManager_Revoke(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		repo            *mocks.MockTokenRepository
	}{
		{
			name:            "Success",
			wantErr:         false,
			expectedErrCode: "",
			repo: &mocks.MockTokenRepository{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:            "Internal server error is returned when blacklisting a token",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repo: &mocks.MockTokenRepository{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return errors.New(errors.ErrCodeInternalServerError, "token not found")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenManager(test.repo, nil, nil)
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

func TestTokenManager_GetTokenData(t *testing.T) {
	tests := []struct {
		name              string
		wantErr           bool
		expectedErrCode   string
		expectedTokenData *token.TokenData
		repo              *mocks.MockTokenRepository
	}{
		{
			name:              "Success",
			wantErr:           false,
			expectedErrCode:   "",
			expectedTokenData: getTestTokenData(),
			repo: &mocks.MockTokenRepository{
				GetTokenFunc: func(ctx context.Context, token string) (*token.TokenData, error) {
					return getTestTokenData(), nil
				},
			},
		},
		{
			name:              "Token not found error is returned",
			wantErr:           true,
			expectedErrCode:   errors.SystemErrorCodeMap[errors.ErrCodeTokenNotFound],
			expectedTokenData: nil,
			repo: &mocks.MockTokenRepository{
				GetTokenFunc: func(ctx context.Context, token string) (*token.TokenData, error) {
					return nil, errors.New(errors.ErrCodeTokenNotFound, "token not found")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenManager(test.repo, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			result, err := service.GetTokenData(ctx, "token")

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error codes to be equal")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, result, "Expected result to not be nil")
				assert.Equal(t, test.expectedTokenData.Token, result.Token, "Expected Token values to be equal")
				assert.Equal(t, test.expectedTokenData.ID, result.ID, "Expected ID values to be equal")
				assert.Equal(t, test.expectedTokenData.TokenID, result.TokenID, "Expected TokenID values to be equal")
			}
		})
	}
}

func TestTokenManager_BlacklistToken(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
		repo    *mocks.MockTokenRepository
	}{
		{
			name:    "Success",
			wantErr: false,
			repo: &mocks.MockTokenRepository{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:    "Error while blacklisting token",
			wantErr: true,
			repo: &mocks.MockTokenRepository{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenManager(test.repo, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := service.BlacklistToken(ctx, "token")

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}

func TestTokenManager_DeleteExpiredTokens(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
		repo    *mocks.MockTokenRepository
	}{
		{
			name:    "Success",
			wantErr: false,
			repo: &mocks.MockTokenRepository{
				GetExpiredTokensFunc: func(ctx context.Context) ([]*token.TokenData, error) {
					return []*token.TokenData{}, nil
				},
				DeleteTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:    "Error is returned when retrieving expired tokens",
			wantErr: true,
			repo: &mocks.MockTokenRepository{
				GetExpiredTokensFunc: func(ctx context.Context) ([]*token.TokenData, error) {
					return nil, errors.NewInternalServerError()
				},
			},
		},
		{
			name:    "Error is returned while deleting tokens",
			wantErr: true,
			repo: &mocks.MockTokenRepository{
				GetExpiredTokensFunc: func(ctx context.Context) ([]*token.TokenData, error) {
					return []*token.TokenData{
						{Token: "token"},
					}, nil
				},
				DeleteTokenFunc: func(ctx context.Context, token string) error {
					return errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenManager(test.repo, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := service.DeleteExpiredTokens(ctx)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}

func TestTokenManager_DeleteToken(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
		repo    *mocks.MockTokenRepository
	}{
		{
			name:    "Success",
			wantErr: false,
			repo: &mocks.MockTokenRepository{
				DeleteTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:    "Error is returned when deleting a token",
			wantErr: true,
			repo: &mocks.MockTokenRepository{
				DeleteTokenFunc: func(ctx context.Context, token string) error {
					return errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenManager(test.repo, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := service.DeleteToken(ctx, "token")

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
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

func getTestTokenData() *token.TokenData {
	return &token.TokenData{
		Token:       "token",
		ID:          "test-ID",
		TokenID:     "token-1234",
		TokenClaims: getTestTokenClaims(),
	}
}
