package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

func TestTokenIssuer_IssueTokenPair(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		creator     *mocks.MockTokenCreator
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			creator: &mocks.MockTokenCreator{
				CreateAccessTokenWithClaimsFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *domain.ClaimsRequest) (string, error) {
					return "token", nil
				},
				CreateRefreshTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string) (string, error) {
					return "refreshToken", nil
				},
			},
		},
		{
			name:        "Internal server error is returned when issuing access token",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			creator: &mocks.MockTokenCreator{
				CreateAccessTokenWithClaimsFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *domain.ClaimsRequest) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
		{
			name:        "Internal server error is returned when issuing refresh token",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			creator: &mocks.MockTokenCreator{
				CreateAccessTokenWithClaimsFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *domain.ClaimsRequest) (string, error) {
					return "token", nil
				},
				CreateRefreshTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewTokenIssuer(test.creator)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			accessToken, refreshToken, err := sut.IssueTokenPair(
				ctx,
				"subject",
				"audience",
				types.OpenIDScope,
				"",
				"nonce",
				nil,
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected errors to be equal")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotEmpty(t, accessToken)
				assert.NotEmpty(t, refreshToken)
			}
		})
	}
}

func TestTokenIssuer_IssueIDToken(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		creator     *mocks.MockTokenCreator
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			creator: &mocks.MockTokenCreator{
				CreateIDTokenFunc: func(ctx context.Context, userID, clientID string, scopes types.Scope, nonce string, acrValues string, authTime time.Time) (string, error) {
					return "idToken", nil
				},
			},
		},
		{
			name:        "Internal server error is returned when issuing the ID token",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			creator: &mocks.MockTokenCreator{
				CreateIDTokenFunc: func(ctx context.Context, userID, clientID string, scopes types.Scope, nonce string, acrValues string, authTime time.Time) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewTokenIssuer(test.creator)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			IDToken, err := sut.IssueIDToken(
				ctx,
				"sub",
				"audience",
				types.OpenIDScope,
				"nonce",
				"1 2",
				time.Now(),
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected errors to be equal")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotEmpty(t, IDToken)
			}
		})
	}
}

func TestTokenIssuer_IssueAccessToken(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		creator     *mocks.MockTokenCreator
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			creator: &mocks.MockTokenCreator{
				CreateAccessTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string) (string, error) {
					return "token", nil
				},
			},
		},
		{
			name:        "Internal server error is returned when issuing the ID token",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			creator: &mocks.MockTokenCreator{
				CreateAccessTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewTokenIssuer(test.creator)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			IDToken, err := sut.IssueAccessToken(
				ctx,
				"sub",
				"audience",
				types.OpenIDScope,
				"",
				"nonce",
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected errors to be equal")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotEmpty(t, IDToken)
			}
		})
	}
}
