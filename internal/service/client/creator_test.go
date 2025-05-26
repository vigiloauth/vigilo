package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	clientMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	encryptionMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/crypto"
	tokenMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

func TestClientCreator_Register(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		client      *domain.ClientRegistrationRequest
		repo        *clientMocks.MockClientRepository
		validator   *clientMocks.MockClientValidator
		issuer      *tokenMocks.MockTokenIssuer
		encryptor   *encryptionMocks.MockCryptographer
	}{
		{
			name:        "Successful public client registration",
			wantErr:     false,
			expectedErr: "",
			client: &domain.ClientRegistrationRequest{
				Name: "Test-Client",
				Type: types.PublicClient,
			},
			repo: &clientMocks.MockClientRepository{
				SaveClientFunc: func(ctx context.Context, client *domain.Client) error {
					return nil
				},
			},
			validator: &clientMocks.MockClientValidator{
				ValidateRegistrationRequestFunc: func(ctx context.Context, req *domain.ClientRegistrationRequest) error {
					return nil
				},
			},
			issuer: &tokenMocks.MockTokenIssuer{
				IssueAccessTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string) (string, error) {
					return "token", nil
				},
			},
		},
		{
			name:        "Successful confidential client registration",
			wantErr:     false,
			expectedErr: "",
			client: &domain.ClientRegistrationRequest{
				Name: "Test-Client",
				Type: types.ConfidentialClient,
			},
			repo: &clientMocks.MockClientRepository{
				SaveClientFunc: func(ctx context.Context, client *domain.Client) error {
					return nil
				},
			},
			validator: &clientMocks.MockClientValidator{
				ValidateRegistrationRequestFunc: func(ctx context.Context, req *domain.ClientRegistrationRequest) error {
					return nil
				},
			},
			issuer: &tokenMocks.MockTokenIssuer{
				IssueAccessTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string) (string, error) {
					return "token", nil
				},
			},
			encryptor: &encryptionMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "secret", nil
				},
				HashStringFunc: func(plainStr string) (string, error) {
					return "hashedSecret", nil
				},
			},
		},
		{
			name:        "Failed registration due to token issuance error",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			client: &domain.ClientRegistrationRequest{
				Name: "Test-Client",
				Type: types.ConfidentialClient,
			},
			validator: &clientMocks.MockClientValidator{
				ValidateRegistrationRequestFunc: func(ctx context.Context, req *domain.ClientRegistrationRequest) error {
					return nil
				},
			},
			issuer: &tokenMocks.MockTokenIssuer{
				IssueAccessTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string) (string, error) {
					return "", errors.NewInternalServerError()
				},
			},
			encryptor: &encryptionMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "secret", nil
				},
				HashStringFunc: func(plainStr string) (string, error) {
					return "hashedSecret", nil
				},
			},
		},
		{
			name:        "Failed registration due to repository save error",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			client: &domain.ClientRegistrationRequest{
				Name: "Test-Client",
				Type: types.ConfidentialClient,
			},
			validator: &clientMocks.MockClientValidator{
				ValidateRegistrationRequestFunc: func(ctx context.Context, req *domain.ClientRegistrationRequest) error {
					return nil
				},
			},
			repo: &clientMocks.MockClientRepository{
				SaveClientFunc: func(ctx context.Context, client *domain.Client) error {
					return errors.NewInternalServerError()
				},
			},
			issuer: &tokenMocks.MockTokenIssuer{
				IssueAccessTokenFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string) (string, error) {
					return "token", nil
				},
			},
			encryptor: &encryptionMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "secret", nil
				},
				HashStringFunc: func(plainStr string) (string, error) {
					return "hashedSecret", nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewClientCreator(test.repo, test.validator, test.issuer, test.encryptor)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			res, err := sut.Register(ctx, test.client)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to match")
				assert.Nil(t, res, "Expected result to be nil but got: %v", res)
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, res, "Expected result to not be nil")
			}
		})
	}
}
