package service

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	jwtMock "github.com/vigiloauth/vigilo/v2/internal/mocks/jwt"
	repo "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

const (
	testScopes    string = "clients:read"
	testAudience  string = "client-1234"
	testSubject   string = "user-1234"
	testNonce     string = "1234abcd"
	testRoles     string = "ADMIN"
	testRequestID string = "req-123456"
	testToken     string = "test-token"
)

func TestTokenService_GenerateToken(t *testing.T) {
	tests := []struct {
		name            string
		tokenType       types.TokenType
		wantErr         bool
		expectedErrCode string
		repository      *repo.MockTokenRepository
	}{
		{
			name:            "Valid access token generation",
			tokenType:       types.AccessTokenType,
			wantErr:         false,
			expectedErrCode: "",
			repository: &repo.MockTokenRepository{
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
			},
		},
		{
			name:            "Valid refresh token generation",
			tokenType:       types.RefreshTokenType,
			wantErr:         false,
			expectedErrCode: "",
			repository: &repo.MockTokenRepository{
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
			},
		},
		{
			name:            "Access token generation fails and returns internal server error",
			tokenType:       types.AccessTokenType,
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repository: &repo.MockTokenRepository{
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return errors.NewInternalServerError()
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
			},
		},
		{
			name:            "Refresh token generation fails and returns internal server error",
			tokenType:       types.RefreshTokenType,
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repository: &repo.MockTokenRepository{
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return errors.NewInternalServerError()
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
			},
		},
		{
			name:            "Unsupported token type returns internal server error",
			tokenType:       "invalid_token",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repository: &repo.MockTokenRepository{
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return errors.NewInternalServerError()
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
			},
		},
		{
			name:            "Error is returned when the token already exists by ID",
			tokenType:       types.AccessTokenType,
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repository: &repo.MockTokenRepository{
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return errors.NewInternalServerError()
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return true, nil
				},
			}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenService(test.repository, nil)

			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)
			result, err := service.GenerateToken(
				ctx,
				testSubject,
				testAudience,
				types.OpenIDScope,
				testRoles,
				testNonce,
				test.tokenType,
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Empty(t, result, "Expected the token string to be empty")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected both error codes to be the same")
			} else {
				assert.Nil(t, err, "Expected no error")
				assert.NotEmpty(t, result, "Expected the token string to not be empty")
			}
		})
	}
}

func TestTokenService_GenerateIDToken(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		repository      *repo.MockTokenRepository
	}{
		{
			name:            "Valid ID Token generation",
			wantErr:         false,
			expectedErrCode: "",
			repository: &repo.MockTokenRepository{
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return nil
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
			},
		},
		{
			name:            "Error saving the ID Token",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repository: &repo.MockTokenRepository{
				SaveTokenFunc: func(ctx context.Context, token, id string, tokenData *tokens.TokenData, expiration time.Time) error {
					return errors.NewInternalServerError()
				},
				ExistsByTokenIDFunc: func(ctx context.Context, tokenID string) (bool, error) {
					return false, nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenService(test.repository, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			result, err := service.GenerateIDToken(
				ctx,
				testSubject,
				testAudience,
				types.OpenIDScope,
				testNonce,
				time.Now(),
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Empty(t, result, "Expected the ID token string to be empty")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected both error codes to be the same")
			} else {
				assert.Nil(t, err, "Expected no error")
				assert.NotEmpty(t, result, "Expected the ID token string to not be empty")
			}
		})
	}
}

func TestTokenService_ParseToken(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		expectedClaims  *tokens.TokenClaims
		jwtService      *jwtMock.MockJWTService
	}{
		{
			name:            "Successful token parsing",
			wantErr:         false,
			expectedErrCode: "",
			expectedClaims: &tokens.TokenClaims{
				Scopes: types.OpenIDScope,
				Roles:  constants.AdminRole,
				Nonce:  testNonce,
				StandardClaims: &jwt.StandardClaims{
					Subject:  testSubject,
					Audience: testAudience,
				},
			},
			jwtService: &jwtMock.MockJWTService{
				ParseWithClaimsFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return &tokens.TokenClaims{
						Scopes: types.OpenIDScope,
						Roles:  constants.AdminRole,
						Nonce:  testNonce,
						StandardClaims: &jwt.StandardClaims{
							Subject:  testSubject,
							Audience: testAudience,
						},
					}, nil
				},
			},
		},
		{
			name:            "Internal server error is returned when failing to parse token",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			expectedClaims:  nil,
			jwtService: &jwtMock.MockJWTService{
				ParseWithClaimsFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return nil, errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenService(nil, test.jwtService)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			claims, err := service.ParseToken(ctx, testToken)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, claims, "Expected claims to be nil")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, claims, "Expected claims to not be nil")
				assert.Equal(t, test.expectedClaims.Scopes, claims.Scopes, "Expected scope values to be equal")
				assert.Equal(t, test.expectedClaims.Roles, claims.Roles, "Expected role values to be equal")
				assert.Equal(t, test.expectedClaims.Nonce, claims.Nonce, "Expected nonce values to be equal")
				assert.Equal(t, test.expectedClaims.StandardClaims.Subject, claims.StandardClaims.Subject, "Expected subject values to be equal")
				assert.Equal(t, test.expectedClaims.StandardClaims.Audience, claims.StandardClaims.Audience, "Expected audience values to be equal")
			}
		})
	}
}

func TestTokenService_BlacklistToken(t *testing.T) {
	tests := []struct {
		name       string
		tokenStr   string
		wantErr    bool
		repository *repo.MockTokenRepository
	}{
		{
			name:     "Token blacklisting is successful",
			tokenStr: testToken,
			wantErr:  false,
			repository: &repo.MockTokenRepository{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:     "Error is returned when blacklisting a token",
			tokenStr: testToken,
			wantErr:  true,
			repository: &repo.MockTokenRepository{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenService(test.repository, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := service.BlacklistToken(ctx, test.tokenStr)

			if test.wantErr {
				assert.Error(t, err, "expected an error when blacklisting a token")
			} else {
				assert.NoError(t, err, "expected no error when blacklisting a token")
			}
		})
	}
}

func TestTokenService_GetTokenData(t *testing.T) {
	tests := []struct {
		name              string
		expectedTokenData *tokens.TokenData
		wantErr           bool
		expectedErrCode   string
		repository        *repo.MockTokenRepository
	}{
		{
			name:            "Successful token retrieval",
			wantErr:         false,
			expectedErrCode: "",
			expectedTokenData: &tokens.TokenData{
				Token:   testToken,
				ID:      testAudience,
				TokenID: testSubject,
			},
			repository: &repo.MockTokenRepository{
				GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
					return &tokens.TokenData{
						Token:   testToken,
						ID:      testAudience,
						TokenID: testSubject,
					}, nil
				},
			},
		},
		{
			name:              "Token not found error is returned when the token does not exist",
			wantErr:           true,
			expectedErrCode:   errors.SystemErrorCodeMap[errors.ErrCodeTokenNotFound],
			expectedTokenData: nil,
			repository: &repo.MockTokenRepository{
				GetTokenFunc: func(ctx context.Context, token string) (*tokens.TokenData, error) {
					return nil, errors.New(errors.ErrCodeTokenNotFound, "token not found")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenService(test.repository, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			tokenData, err := service.GetTokenData(ctx, testToken)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, tokenData, "Expected the token data to be nil")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err))
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, tokenData, "Expected token data not to be nil")
				assert.Equal(t, test.expectedTokenData.Token, tokenData.Token, "Expected token values to be equal")
				assert.Equal(t, test.expectedTokenData.ID, tokenData.ID, "Expected ID values to be equal")
				assert.Equal(t, test.expectedTokenData.TokenID, tokenData.TokenID, "Expected token ID values to be equal")
			}
		})
	}
}

func TestTokenService_DeleteToken(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		repository      *repo.MockTokenRepository
	}{
		{
			name:            "Successful token deletion",
			wantErr:         false,
			expectedErrCode: "",
			repository: &repo.MockTokenRepository{
				DeleteTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:            "Token not found error is returned when the token does not exist",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeTokenNotFound],
			repository: &repo.MockTokenRepository{
				DeleteTokenFunc: func(ctx context.Context, token string) error {
					return errors.New(errors.ErrCodeTokenNotFound, "token not found")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenService(test.repository, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := service.DeleteToken(ctx, testToken)

			if test.wantErr {
				assert.Error(t, err, "Expected an error when deleting a token but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error codes to be equal")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}

func TestTokenService_ValidateToken(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		repository      *repo.MockTokenRepository
		jwtService      *jwtMock.MockJWTService
	}{
		{
			name:            "Successful token validation",
			wantErr:         false,
			expectedErrCode: "",
			repository: &repo.MockTokenRepository{
				IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
					return false, nil
				},
			},
			jwtService: &jwtMock.MockJWTService{
				ParseWithClaimsFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return &tokens.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
						},
					}, nil
				},
			},
		},
		{
			name:            "Error is returned when the token is expired",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeExpiredToken],
			repository:      nil,
			jwtService: &jwtMock.MockJWTService{
				ParseWithClaimsFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token with claims")
				},
			},
		},
		{
			name:            "Error is returned when the token is blacklisted",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			repository: &repo.MockTokenRepository{
				IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
					return true, nil
				},
			},
			jwtService: &jwtMock.MockJWTService{
				ParseWithClaimsFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return &tokens.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
						},
					}, nil
				},
			},
		},
		{
			name:            "Error is returned when retrieving the token",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repository: &repo.MockTokenRepository{
				IsTokenBlacklistedFunc: func(ctx context.Context, token string) (bool, error) {
					return true, errors.NewInternalServerError()
				},
			},
			jwtService: &jwtMock.MockJWTService{
				ParseWithClaimsFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return &tokens.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							ExpiresAt: time.Now().Add(2 * time.Hour).Unix(),
						},
					}, nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenService(test.repository, test.jwtService)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := service.ValidateToken(ctx, testToken)

			if test.wantErr {
				assert.Error(t, err, "Expected an error when validating a token but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error codes to be equal")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}

func TestTokenService_DeleteExpiredTokens(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		repository      *repo.MockTokenRepository
	}{
		{
			name:            "Successful deletion of expired tokens",
			wantErr:         false,
			expectedErrCode: "",
			repository: &repo.MockTokenRepository{
				GetExpiredTokensFunc: func(ctx context.Context) ([]*tokens.TokenData, error) {
					return []*tokens.TokenData{}, nil
				},
				DeleteTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewTokenService(test.repository, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := service.DeleteExpiredTokens(ctx)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err))
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}
