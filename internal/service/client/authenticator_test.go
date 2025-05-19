package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mockClient "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	mockToken "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

const (
	testRequestID string = "req-1234"
	testURL       string = "https://localhost.com"
	bearerToken   string = "bearer-token"
)

func TestClientRequestAuthenticator_AuthenticateRequest(t *testing.T) {
	t.Run("Test with basic auth header", func(t *testing.T) {
		tests := []struct {
			name            string
			wantErr         bool
			expectedErrCode string
			clientService   *mockClient.MockClientService
		}{
			{
				name:            "Success",
				wantErr:         false,
				expectedErrCode: "",
				clientService: &mockClient.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) error {
						return nil
					},
				},
			},
			{
				name:            "Unauthorized client is returned on error",
				wantErr:         true,
				expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
				clientService: &mockClient.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) error {
						return errors.New(errors.ErrCodeUnauthorizedClient, "unauthorized client")
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				service := NewClientRequestAuthenticator(test.clientService, nil)
				ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

				req := httptest.NewRequest(http.MethodGet, testURL, nil)
				req.SetBasicAuth(testClientID, testClientSecret)

				err := service.AuthenticateRequest(ctx, req, types.OpenIDScope)

				if test.wantErr {
					assert.Error(t, err, "Expected an error but got none")
					assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error codes to match")
				} else {
					assert.NoError(t, err, "Expected no error but got: %v", err)
				}
			})
		}
	})

	t.Run("Test with bearer token header", func(t *testing.T) {
		tests := []struct {
			name            string
			wantErr         bool
			expectedErrCode string
			clientService   *mockClient.MockClientService
			tokenService    *mockToken.MockTokenService
		}{
			{
				name:            "Success",
				wantErr:         false,
				expectedErrCode: "",
				tokenService: &mockToken.MockTokenService{
					ValidateTokenFunc: func(ctx context.Context, token string) error {
						return nil
					},
					ParseTokenFunc: func(ctx context.Context, tokenStr string) (*tokens.TokenClaims, error) {
						return &tokens.TokenClaims{
							StandardClaims: &jwt.StandardClaims{
								Audience: "client-1234",
							},
						}, nil
					},
				},
				clientService: &mockClient.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) error {
						return nil
					},
				},
			},
			{
				name:            "Expired token error is returned",
				wantErr:         true,
				expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeExpiredToken],
				tokenService: &mockToken.MockTokenService{
					ValidateTokenFunc: func(ctx context.Context, token string) error {
						return errors.New(errors.ErrCodeExpiredToken, "token is expired")
					},
				},
			},
			{
				name:            "Internal server error is returned when parsing token",
				wantErr:         true,
				expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
				tokenService: &mockToken.MockTokenService{
					ValidateTokenFunc: func(ctx context.Context, token string) error {
						return nil
					},
					ParseTokenFunc: func(ctx context.Context, tokenStr string) (*tokens.TokenClaims, error) {
						return nil, errors.NewInternalServerError()
					},
				},
			},
			{
				name:            "Unauthorized client error is returned",
				wantErr:         true,
				expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
				tokenService: &mockToken.MockTokenService{
					ValidateTokenFunc: func(ctx context.Context, token string) error {
						return nil
					},
					ParseTokenFunc: func(ctx context.Context, tokenStr string) (*tokens.TokenClaims, error) {
						return &tokens.TokenClaims{
							StandardClaims: &jwt.StandardClaims{
								Audience: "client-1234",
							},
						}, nil
					},
				},
				clientService: &mockClient.MockClientService{
					AuthenticateClientFunc: func(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) error {
						return errors.New(errors.ErrCodeUnauthorizedClient, "unauthorized client")
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				service := NewClientRequestAuthenticator(test.clientService, test.tokenService)
				ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

				req := httptest.NewRequest(http.MethodGet, testURL, nil)
				req.Header.Set(constants.AuthorizationHeader, constants.BearerAuthHeader+bearerToken)

				err := service.AuthenticateRequest(ctx, req, types.OpenIDScope)

				if test.wantErr {
					assert.Error(t, err, "Expected an error but got none")
					assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error codes to match")
				} else {
					assert.NoError(t, err, "Expected no error but got: %v", err)
				}
			})
		}
	})
}
