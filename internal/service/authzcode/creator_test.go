package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	authzCodeMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/authzcode"
	cryptoMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/crypto"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

const (
	clientID    string = "client-123"
	userID      string = "user-123"
	redirectURI string = "https://example.com/callback"
	nonce       string = "nonce-123"
)

func TestAuthorizationCodeCreator_GenerateAuthorizationCode(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		request         *client.ClientAuthorizationRequest
		repo            *authzCodeMocks.MockAuthorizationCodeRepository
		cryptographer   *cryptoMocks.MockCryptographer
	}{
		{
			name:            "Success",
			wantErr:         false,
			expectedErrCode: "",
			request:         createClientAuthorizationRequest(false),
			cryptographer: &cryptoMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "authz-code-123", nil
				},
			},
			repo: &authzCodeMocks.MockAuthorizationCodeRepository{
				StoreAuthorizationCodeFunc: func(ctx context.Context, code string, data *domain.AuthorizationCodeData, expiresAt time.Time) error {
					return nil
				},
			},
		},
		{
			name:            "Success when client requires PKCE",
			wantErr:         false,
			expectedErrCode: "",
			request:         createClientAuthorizationRequest(true),
			cryptographer: &cryptoMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "authz-code-pkce-123", nil
				},
			},
			repo: &authzCodeMocks.MockAuthorizationCodeRepository{
				StoreAuthorizationCodeFunc: func(ctx context.Context, code string, data *domain.AuthorizationCodeData, expiresAt time.Time) error {
					return nil
				},
			},
		},
		{
			name:            "Random generation error is returned when generating authorization code for PKCE",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeRandomGenerationFailed],
			request:         createClientAuthorizationRequest(true),
			cryptographer: &cryptoMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "", errors.New(errors.ErrCodeRandomGenerationFailed, "failed to generate random string")
				},
			},
		},
		{
			name:            "Random generation error is returned when generating authorization code",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeRandomGenerationFailed],
			request:         createClientAuthorizationRequest(false),
			cryptographer: &cryptoMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "", errors.New(errors.ErrCodeRandomGenerationFailed, "failed to generate random string")
				},
			},
		},
		{
			name:            "Internal server error is returned when storing authorization code",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			request:         createClientAuthorizationRequest(false),
			cryptographer: &cryptoMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "authz-code-123", nil
				},
			},
			repo: &authzCodeMocks.MockAuthorizationCodeRepository{
				StoreAuthorizationCodeFunc: func(ctx context.Context, code string, data *domain.AuthorizationCodeData, expiresAt time.Time) error {
					return errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewAuthorizationCodeCreator(test.repo, test.cryptographer)
			ctx := context.Background()

			code, err := sut.GenerateAuthorizationCode(ctx, test.request)
			if test.wantErr {
				assert.Error(t, err, "Expected error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
				assert.Empty(t, code, "Expected empty code on error")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.NotEmpty(t, code, "Expected a non-empty code")
			}
		})
	}
}

func createClientAuthorizationRequest(requiredPKCE bool) *client.ClientAuthorizationRequest {
	return &client.ClientAuthorizationRequest{
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       types.OpenIDScope,
		Nonce:       nonce,
		Client: &client.Client{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			RequiresPKCE: requiredPKCE,
			Scopes:       []types.Scope{types.OpenIDScope},
		},
		UserAuthenticationTime: time.Now().UTC(),
		ClaimsRequest: &claims.ClaimsRequest{
			UserInfo: &claims.ClaimSet{
				"email": &claims.ClaimSpec{
					Essential: true,
				},
			},
		},
	}
}
