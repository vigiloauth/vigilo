package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/authzcode"
	clientMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

const (
	code string = "test-code"
)

func TestAuthorizationCodeValidator_ValidateRequest(t *testing.T) {
	tests := []struct {
		name                string
		wantErr             bool
		expectedErrCode     string
		req                 *client.ClientAuthorizationRequest
		clientValidator     *clientMocks.MockClientValidator
		clientAuthenticator *clientMocks.MockClientAuthenticator
	}{
		{
			name:            "Success",
			wantErr:         false,
			expectedErrCode: "",
			req: &client.ClientAuthorizationRequest{
				ClientID:    "client-id",
				Scope:       types.OpenIDScope,
				RedirectURI: "https://example.com/callback",
				Client: &client.Client{
					ID:     "client-id",
					Secret: "secret",
				},
			},
			clientValidator: &clientMocks.MockClientValidator{
				ValidateAuthorizationRequestFunc: func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
					return nil
				},
			},
			clientAuthenticator: &clientMocks.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *client.ClientAuthenticationRequest) error {
					return nil
				},
			},
		},
		{
			name:            "Invalid request error is returned authenticating client",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInvalidRequest],
			req: &client.ClientAuthorizationRequest{
				ClientID:    "client-id",
				Scope:       types.OpenIDScope,
				RedirectURI: "https://example.com/callback",
				Client: &client.Client{
					ID:     "client-id",
					Secret: "secret",
				},
			},
			clientValidator: &clientMocks.MockClientValidator{
				ValidateAuthorizationRequestFunc: func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
					return errors.New(errors.ErrCodeInvalidRequest, "invalid request")
				},
			},
		},
		{
			name:            "Unauthorized client error is returned authorizing the request",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
			req: &client.ClientAuthorizationRequest{
				ClientID:    "client-id",
				Scope:       types.OpenIDScope,
				RedirectURI: "https://example.com/callback",
				Client: &client.Client{
					ID:     "client-id",
					Secret: "secret",
				},
			},
			clientValidator: &clientMocks.MockClientValidator{
				ValidateAuthorizationRequestFunc: func(ctx context.Context, req *client.ClientAuthorizationRequest) error {
					return nil
				},
			},
			clientAuthenticator: &clientMocks.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *client.ClientAuthenticationRequest) error {
					return errors.New(errors.ErrCodeUnauthorizedClient, "invalid credentials")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			sut := NewAuthorizationCodeValidator(
				nil,
				test.clientValidator,
				test.clientAuthenticator,
			)

			err := sut.ValidateRequest(ctx, test.req)
			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
			}
		})
	}
}

func TestAuthorizationCodeValidator_ValidateAuthorizationCode(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		code            string
		clientID        string
		redirectURI     string
		repo            *mocks.MockAuthorizationCodeRepository
	}{
		{
			name:            "Success",
			wantErr:         false,
			expectedErrCode: "",
			code:            code,
			clientID:        clientID,
			redirectURI:     redirectURI,
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return &domain.AuthorizationCodeData{
						Used:        false,
						ClientID:    clientID,
						RedirectURI: redirectURI,
					}, nil
				},
			},
		},
		{
			name:            "Invalid grant error is returned when code has been used",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInvalidGrant],
			code:            code,
			clientID:        clientID,
			redirectURI:     redirectURI,
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return &domain.AuthorizationCodeData{
						Used:        true,
						ClientID:    clientID,
						RedirectURI: redirectURI,
					}, nil
				},
			},
		},
		{
			name:            "Code not found error is returned",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeAuthorizationCodeNotFound],
			code:            code,
			clientID:        clientID,
			redirectURI:     redirectURI,
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return nil, errors.New(errors.ErrCodeAuthorizationCodeNotFound, "authorization code not found")
				},
			},
		},
		{
			name:            "Invalid grant error is returned when client IDs don't match",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInvalidGrant],
			code:            code,
			clientID:        "different-client-id",
			redirectURI:     redirectURI,
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return &domain.AuthorizationCodeData{
						Used:        false,
						ClientID:    clientID,
						RedirectURI: redirectURI,
					}, nil
				},
			},
		},
		{
			name:            "Invalid grant error URI error is returned when redirect URIs do not match",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInvalidGrant],
			code:            code,
			clientID:        clientID,
			redirectURI:     "https://different-redirect-uri.com/callback",
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return &domain.AuthorizationCodeData{
						Used:        false,
						ClientID:    clientID,
						RedirectURI: redirectURI,
					}, nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewAuthorizationCodeValidator(test.repo, nil, nil)
			ctx := context.Background()

			err := sut.ValidateAuthorizationCode(ctx, test.code, test.clientID, test.redirectURI)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
			}
		})
	}
}

func TestAuthorizationCodeValidator_ValidatePKCE(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		authzCodeData   *domain.AuthorizationCodeData
		codeVerifier    string
	}{
		{
			name:            "Success with SHA256 method",
			wantErr:         false,
			expectedErrCode: "",
			authzCodeData: &domain.AuthorizationCodeData{
				CodeChallengeMethod: types.SHA256CodeChallengeMethod,
				CodeChallenge:       utils.EncodeSHA256("valid-verifier"),
			},
			codeVerifier: "valid-verifier",
		},
		{
			name:            "Success with plain method",
			wantErr:         false,
			expectedErrCode: "",
			authzCodeData: &domain.AuthorizationCodeData{
				CodeChallengeMethod: types.PlainCodeChallengeMethod,
				CodeChallenge:       "valid-verifier",
			},
			codeVerifier: "valid-verifier",
		},
		{
			name:            "Invalid code verifier with SHA256 method",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInvalidGrant],
			authzCodeData: &domain.AuthorizationCodeData{
				CodeChallengeMethod: types.SHA256CodeChallengeMethod,
				CodeChallenge:       utils.EncodeSHA256("valid-verifier"),
			},
			codeVerifier: "invalid-verifier",
		},
		{
			name:            "Invalid code verifier with plain method",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInvalidGrant],
			authzCodeData: &domain.AuthorizationCodeData{
				CodeChallengeMethod: types.PlainCodeChallengeMethod,
				CodeChallenge:       "valid-verifier",
			},
			codeVerifier: "invalid-verifier",
		},
		{
			name:            "Unsupported code challenge method",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			authzCodeData: &domain.AuthorizationCodeData{
				CodeChallengeMethod: "unsupported-method",
				CodeChallenge:       "valid-verifier",
			},
			codeVerifier: "valid-verifier",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			sut := NewAuthorizationCodeValidator(nil, nil, nil)

			err := sut.ValidatePKCE(ctx, test.authzCodeData, test.codeVerifier)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
			}
		})
	}
}
