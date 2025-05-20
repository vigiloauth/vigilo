package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	clients "github.com/vigiloauth/vigilo/v2/internal/domain/client"
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
	clientID      string = "client-1234"
	secret        string = "clientSecret"
)

func TestClientAuthenticator_AuthenticateRequest(t *testing.T) {
	t.Run("Test with basic auth header", func(t *testing.T) {
		tests := []struct {
			name            string
			wantErr         bool
			expectedErrCode string
			clientRepo      *mockClient.MockClientRepository
		}{
			{
				name:            "Success",
				wantErr:         false,
				expectedErrCode: "",
				clientRepo: &mockClient.MockClientRepository{
					GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
						return &clients.Client{
							ID:     clientID,
							Secret: secret,
							Type:   types.ConfidentialClient,
							Scopes: []types.Scope{types.OpenIDScope},
						}, nil
					},
				},
			},
			{
				name:            "Client not found error is returned when client does not exist",
				wantErr:         true,
				expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeClientNotFound],
				clientRepo: &mockClient.MockClientRepository{
					GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
						return nil, errors.New(errors.ErrCodeClientNotFound, "client not found")
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				service := NewClientAuthenticator(test.clientRepo, nil, nil)
				ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

				req := httptest.NewRequest(http.MethodGet, testURL, nil)
				req.SetBasicAuth(clientID, secret)

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
			clientRepo      *mockClient.MockClientRepository
			tokenParser     *mockToken.MockTokenParser
			tokenValidator  *mockToken.MockTokenValidator
		}{
			{
				name:            "Success",
				wantErr:         false,
				expectedErrCode: "",
				tokenValidator: &mockToken.MockTokenValidator{
					ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
						return nil
					},
				},
				tokenParser: &mockToken.MockTokenParser{
					ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
						return &tokens.TokenClaims{
							StandardClaims: &jwt.StandardClaims{
								Audience: clientID,
							},
						}, nil
					},
				},
				clientRepo: &mockClient.MockClientRepository{
					GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
						return &clients.Client{
							ID:     clientID,
							Secret: secret,
							Type:   types.ConfidentialClient,
							Scopes: []types.Scope{types.OpenIDScope},
						}, nil
					},
				},
			},
			{
				name:            "Expired token error is returned",
				wantErr:         true,
				expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeExpiredToken],
				tokenValidator: &mockToken.MockTokenValidator{
					ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
						return errors.New(errors.ErrCodeExpiredToken, "token is expired")
					},
				},
			},
			{
				name:            "Token parsing error is returned when parsing the token fails",
				wantErr:         true,
				expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeTokenParsing],
				tokenValidator: &mockToken.MockTokenValidator{
					ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
						return nil
					},
				},
				tokenParser: &mockToken.MockTokenParser{
					ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
						return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
					},
				},
			},
			{
				name:            "Insufficient scope error is returned",
				wantErr:         true,
				expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInsufficientScope],
				tokenValidator: &mockToken.MockTokenValidator{
					ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
						return nil
					},
				},
				tokenParser: &mockToken.MockTokenParser{
					ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
						return &tokens.TokenClaims{
							StandardClaims: &jwt.StandardClaims{
								Audience: clientID,
							},
						}, nil
					},
				},
				clientRepo: &mockClient.MockClientRepository{
					GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
						return &clients.Client{
							ID: clientID,
						}, nil
					},
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				service := NewClientAuthenticator(test.clientRepo, test.tokenValidator, test.tokenParser)
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

func TestClientAuthenticator_AuthenticateClient(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		clientID        string
		clientSecret    string
		requestedGrant  string
		requestedScopes types.Scope
		clientRepo      *mockClient.MockClientRepository
	}{
		{
			name:            "Success",
			wantErr:         false,
			expectedErrCode: "",
			clientID:        clientID,
			clientSecret:    secret,
			requestedGrant:  constants.AuthorizationCodeGrantType,
			requestedScopes: types.OpenIDScope,
			clientRepo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return &clients.Client{
						ID:               clientID,
						Secret:           secret,
						Type:             types.ConfidentialClient,
						CanRequestScopes: true,
						GrantTypes:       []string{constants.AuthorizationCodeGrantType},
					}, nil
				},
			},
		},
		{
			name:            "Client not found error is returned",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeClientNotFound],
			clientID:        clientID,
			clientSecret:    secret,
			requestedGrant:  constants.AuthorizationCodeGrantType,
			requestedScopes: types.OpenIDScope,
			clientRepo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return nil, errors.New(errors.ErrCodeClientNotFound, "not found")
				},
			},
		},
		{
			name:            "Unauthorized client is returned when client is not confidential and a secret is provided",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
			clientID:        clientID,
			clientSecret:    secret,
			requestedGrant:  constants.AuthorizationCodeGrantType,
			requestedScopes: types.OpenIDScope,
			clientRepo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return &clients.Client{
						Type: types.PublicClient,
					}, nil
				},
			},
		},
		{
			name:            "Invalid client error is returned when secrets do not match",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInvalidClient],
			clientID:        clientID,
			clientSecret:    secret,
			requestedGrant:  constants.AuthorizationCodeGrantType,
			requestedScopes: types.OpenIDScope,
			clientRepo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return &clients.Client{
						Type:   types.ConfidentialClient,
						Secret: "invalid-secret",
					}, nil
				},
			},
		},
		{
			name:            "Insufficient scope error is returned when client does not have required scopes",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInsufficientScope],
			clientID:        clientID,
			clientSecret:    secret,
			requestedGrant:  constants.AuthorizationCodeGrantType,
			requestedScopes: types.OpenIDScope,
			clientRepo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return &clients.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
						Scopes: []types.Scope{},
					}, nil
				},
			},
		},
		{
			name:            "Unauthorized client is returned when the client does not have the requested grant",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
			clientID:        clientID,
			clientSecret:    secret,
			requestedGrant:  constants.AuthorizationCodeGrantType,
			requestedScopes: types.OpenIDScope,
			clientRepo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return &clients.Client{
						ID:               clientID,
						Secret:           secret,
						Type:             types.ConfidentialClient,
						CanRequestScopes: true,
						GrantTypes:       []string{constants.ClientCredentialsGrantType},
					}, nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewClientAuthenticator(test.clientRepo, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := service.AuthenticateClient(
				ctx,
				test.clientID,
				test.clientSecret,
				test.requestedGrant,
				test.requestedScopes,
			)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error cods to be equal")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}
