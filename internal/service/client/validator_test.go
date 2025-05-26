package service

import (
	"context"
	"fmt"
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

const validCodeChallenge string = "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_"

func TestClientValidator_ValidateRegistrationRequest(t *testing.T) {
	sut := NewClientValidator(nil, nil, nil, nil)
	ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

	t.Run("Successful Validation", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.Scopes = []types.Scope{}
		err := sut.ValidateRegistrationRequest(ctx, client)
		assert.NoError(t, err)
	})

	t.Run("Invalid Grant Types", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.ApplicationType = constants.NativeApplicationType
		client.TokenEndpointAuthMethod = types.NoTokenAuth
		client.GrantTypes = append(client.GrantTypes, constants.ClientCredentialsGrantType)

		err := sut.ValidateRegistrationRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid Redirect URIS", func(t *testing.T) {
		invalidRedirectURI := "http:/missing-slash/callback"
		client := createClientRegistrationRequest()
		client.RedirectURIs = append(client.RedirectURIs, invalidRedirectURI)

		err := sut.ValidateRegistrationRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid Scopes", func(t *testing.T) {
		invalidScope := "update"
		client := createClientRegistrationRequest()
		client.Scopes = append(client.Scopes, types.Scope(invalidScope))

		err := sut.ValidateRegistrationRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid Response Types", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.ResponseTypes = []string{constants.TokenResponseType}

		err := sut.ValidateRegistrationRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid JWKS URI", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.JwksURI = "http/invalid.org/public_keys.jwks"

		err := sut.ValidateRegistrationRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid Logo URI", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.LogoURI = "http/invalid.org/logo.png"

		err := sut.ValidateRegistrationRequest(ctx, client)
		assert.Error(t, err)
	})
}

func TestClientValidator_ValidateUpdateRequest(t *testing.T) {
	sut := NewClientValidator(nil, nil, nil, nil)
	ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

	t.Run("Successful Validation", func(t *testing.T) {
		client := createClientUpdateRequest()
		err := sut.ValidateUpdateRequest(ctx, client)
		assert.NoError(t, err)
	})

	t.Run("Invalid Grant Types", func(t *testing.T) {
		client := createClientUpdateRequest()
		client.GrantTypes = append(client.GrantTypes, constants.ClientCredentialsGrantType)

		err := sut.ValidateUpdateRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid Redirect URIS", func(t *testing.T) {
		invalidRedirectURI := "http:/missing-slash/callback"
		client := createClientUpdateRequest()
		client.RedirectURIs = append(client.RedirectURIs, invalidRedirectURI)

		err := sut.ValidateUpdateRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid Scopes", func(t *testing.T) {
		invalidScope := "update"
		client := createClientUpdateRequest()
		client.Scopes = append(client.Scopes, types.Scope(invalidScope))

		err := sut.ValidateUpdateRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid Response Types", func(t *testing.T) {
		client := createClientUpdateRequest()
		client.ResponseTypes = []string{constants.TokenResponseType}

		err := sut.ValidateUpdateRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid JWKS URI", func(t *testing.T) {
		client := createClientUpdateRequest()
		client.JwksURI = "http/invalid.org/public_keys.jwks"

		err := sut.ValidateUpdateRequest(ctx, client)
		assert.Error(t, err)
	})

	t.Run("Invalid Logo URI", func(t *testing.T) {
		client := createClientUpdateRequest()
		client.LogoURI = "http/invalid.org/logo.png"

		err := sut.ValidateUpdateRequest(ctx, client)
		assert.Error(t, err)
	})
}

func TestClientValidator_ValidateAuthorizationRequest(t *testing.T) {
	sut := NewClientValidator(nil, nil, nil, nil)
	ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

	t.Run("Validation successful", func(t *testing.T) {
		tests := []struct {
			name    string
			request *clients.ClientAuthorizationRequest
		}{
			{
				name: "Valid Base64 URL-encoded string (43-44 chars)",
				request: &clients.ClientAuthorizationRequest{
					Client:              createClient(),
					ResponseType:        constants.CodeResponseType,
					CodeChallenge:       "abcdEFGHijklMNOPqrstUVWasdasd2dasXyz0123456789-_",
					CodeChallengeMethod: types.SHA256CodeChallengeMethod,
					RedirectURI:         "https://www.example-app.com/callback",
				},
			},
			{
				name: "Valid long Base64 URL-encoded string (greater than 44 chars)",
				request: &clients.ClientAuthorizationRequest{
					Client:              createClient(),
					ResponseType:        constants.CodeResponseType,
					CodeChallenge:       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
					CodeChallengeMethod: types.SHA256CodeChallengeMethod,
					RedirectURI:         "https://www.example-app.com/callback",
				},
			},
		}

		for _, test := range tests {
			err := sut.ValidateAuthorizationRequest(ctx, test.request)
			assert.NoError(t, err, fmt.Sprintf("expected no error for %s", test.name))
		}
	})

	t.Run("Error is returned when the code challenge contains invalid characters", func(t *testing.T) {
		tests := []struct {
			name    string
			request *clients.ClientAuthorizationRequest
		}{
			{
				name: "Code challenge contains invalid characters (+, /)",
				request: &clients.ClientAuthorizationRequest{
					Client:              createClient(),
					ResponseType:        constants.CodeResponseType,
					CodeChallenge:       "abcdEFGHijklMNOPqrstUVWXyz01234562345654323456789+/",
					CodeChallengeMethod: types.SHA256CodeChallengeMethod,
					RedirectURI:         "https://www.example-app.com/callback",
				},
			},
			{
				name: "Code challenge contains invalid characters (@, #, !)",
				request: &clients.ClientAuthorizationRequest{
					Client:              createClient(),
					ResponseType:        constants.CodeResponseType,
					CodeChallenge:       "abcdEFGHijklMNOPqrstUVWXyz012345012345678765434567887656789@#!",
					CodeChallengeMethod: types.SHA256CodeChallengeMethod,
					RedirectURI:         "https://www.example-app.com/callback",
				},
			},
		}

		for _, test := range tests {
			err := sut.ValidateAuthorizationRequest(ctx, test.request)
			assert.Error(t, err, fmt.Sprintf("expected error for %s", test.name))
			expectedMessage := "invalid characters: only A-Z, a-z, 0-9, '-', and '_' are allowed (Base64 URL encoding)"
			assert.Contains(t, expectedMessage, err.Error())
		}
	})

	t.Run("Error is returned when the code challenge is too short", func(t *testing.T) {
		request := &clients.ClientAuthorizationRequest{
			CodeChallenge:       "short",
			CodeChallengeMethod: types.SHA256CodeChallengeMethod,
			Client:              createClient(),
			ResponseType:        constants.CodeResponseType,
			RedirectURI:         "https://www.example-app.com/callback",
		}

		err := sut.ValidateAuthorizationRequest(ctx, request)
		expectedErr := fmt.Sprintf("invalid code challenge length (%d): must be between 43 and 128 characters", len(request.CodeChallenge))

		assert.Error(t, err, "expected an error when code challenge is too short")
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Error is returned when the code challenge method is invalid", func(t *testing.T) {
		request := &clients.ClientAuthorizationRequest{
			CodeChallenge:       validCodeChallenge,
			CodeChallengeMethod: "invalid",
			Client:              createClient(),
			ResponseType:        constants.CodeResponseType,
			RedirectURI:         "https://www.example-app.com/callback",
		}

		err := sut.ValidateAuthorizationRequest(ctx, request)
		expectedErr := "invalid code challenge method: 'invalid'. Valid methods are 'plain' and 'SHA-256'"

		assert.Error(t, err, "expected an error when code challenge method is not plain or SHA-256")
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Code challenge method defaults to plain if not present", func(t *testing.T) {
		request := &clients.ClientAuthorizationRequest{
			Client:        createClient(),
			ResponseType:  constants.CodeResponseType,
			CodeChallenge: validCodeChallenge,
			RedirectURI:   "https://www.example-app.com/callback",
		}

		err := sut.ValidateAuthorizationRequest(ctx, request)
		assert.NoError(t, err)
		assert.Equal(t, types.PlainCodeChallengeMethod, request.CodeChallengeMethod)
	})

	t.Run("Error is returned when client does not have 'code' response type", func(t *testing.T) {
		request := &clients.ClientAuthorizationRequest{
			ResponseType: constants.IDTokenResponseType,
			RedirectURI:  "https://www.example-app.com/callback",
			Client: &clients.Client{
				RedirectURIs:  []string{"https://www.example-app.com/callback"},
				Type:          types.PublicClient,
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
				ResponseTypes: []string{constants.IDTokenResponseType},
				RequiresPKCE:  true,
			},
			CodeChallenge: validCodeChallenge,
		}

		err := sut.ValidateAuthorizationRequest(ctx, request)
		expectedError := "code response type is required to receive an authorization code"

		assert.Error(t, err)
		assert.Contains(t, expectedError, err.Error())
	})

	t.Run("Success when request does not have PKCE grant and no code challenge is passed", func(t *testing.T) {
		request := &clients.ClientAuthorizationRequest{
			ResponseType: constants.CodeResponseType,
			RedirectURI:  "https://www.example-app.com/callback",
			Client: &clients.Client{
				RedirectURIs:  []string{"https://www.example-app.com/callback"},
				Type:          types.ConfidentialClient,
				ResponseTypes: []string{constants.CodeResponseType},
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
			},
		}

		err := sut.ValidateAuthorizationRequest(ctx, request)
		assert.NoError(t, err)
	})

	t.Run("Error is returned when the client does not have authorization code grant", func(t *testing.T) {
		request := &clients.ClientAuthorizationRequest{
			Client: &clients.Client{
				RedirectURIs:  []string{"https://www.example-app.com/callback"},
				Type:          types.PublicClient,
				ResponseTypes: []string{constants.CodeResponseType},
			},
			RedirectURI:         "https://www.example-app.com/callback",
			ResponseType:        constants.CodeResponseType,
			CodeChallengeMethod: types.PlainCodeChallengeMethod,
		}

		err := sut.ValidateAuthorizationRequest(ctx, request)
		expectedErr := "authorization code grant is required for this request"

		assert.Error(t, err)
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Error is returned when public client is not using PKCE", func(t *testing.T) {
		request := &clients.ClientAuthorizationRequest{
			Client: &clients.Client{
				RedirectURIs:  []string{"https://www.example-app.com/callback"},
				Type:          types.PublicClient,
				ResponseTypes: []string{constants.CodeResponseType},
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
				RequiresPKCE:  true,
			},
			RedirectURI:         "https://www.example-app.com/callback",
			ResponseType:        constants.CodeResponseType,
			CodeChallengeMethod: types.PlainCodeChallengeMethod,
		}

		err := sut.ValidateAuthorizationRequest(ctx, request)
		expectedErr := "public clients are required to use PKCE"

		assert.Error(t, err)
		assert.Contains(t, err.Error(), expectedErr)
	})

	t.Run("Success when confidential client is not using PKCE", func(t *testing.T) {
		request := &clients.ClientAuthorizationRequest{
			Client: &clients.Client{
				RedirectURIs:  []string{"https://www.example-app.com/callback"},
				Type:          types.ConfidentialClient,
				ResponseTypes: []string{constants.CodeResponseType},
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
			},
			RedirectURI:  "https://www.example-app.com/callback",
			ResponseType: constants.CodeResponseType,
		}

		err := sut.ValidateAuthorizationRequest(ctx, request)
		assert.NoError(t, err)
	})
}

func TestClientValidator_ValidateClientAndRegistrationAccessToken(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		repo        *mockClient.MockClientRepository
		manager     *mockToken.MockTokenManager
		validator   *mockToken.MockTokenValidator
		parser      *mockToken.MockTokenParser
	}{
		{
			name:        "Successful validation",
			wantErr:     false,
			expectedErr: "",
			repo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return &clients.Client{ID: clientID}, nil
				},
			},
			validator: &mockToken.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
			parser: &mockToken.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return &tokens.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							Subject: clientID,
						},
					}, nil
				},
			},
		},
		{
			name:        "Unauthorized error when client does not exist",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			repo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return nil, errors.New(errors.ErrCodeClientNotFound, "invalid credentials")
				},
			},
			manager: &mockToken.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:        "Expired token error when registration access token is expired",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeExpiredToken],
			repo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return &clients.Client{ID: clientID}, nil
				},
			},
			validator: &mockToken.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return errors.New(errors.ErrCodeExpiredToken, "token is expired")
				},
			},
			manager: &mockToken.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:        "Token parsing error is returned when parsing fails",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeTokenParsing],
			repo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return &clients.Client{ID: clientID}, nil
				},
			},
			validator: &mockToken.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
			parser: &mockToken.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
				},
			},
			manager: &mockToken.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:        "Unauthorized error is returned when token subject doesn't match the client ID",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			repo: &mockClient.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*clients.Client, error) {
					return &clients.Client{ID: clientID}, nil
				},
			},
			validator: &mockToken.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
			parser: &mockToken.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
					return &tokens.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							Subject: "invalidID",
						},
					}, nil
				},
			},
			manager: &mockToken.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewClientValidator(test.repo, test.manager, test.validator, test.parser)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := sut.ValidateClientAndRegistrationAccessToken(ctx, clientID, "token")

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected errors to match")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}

func createClientRegistrationRequest() *clients.ClientRegistrationRequest {
	return &clients.ClientRegistrationRequest{
		Name:                    "Test Client",
		Type:                    types.PublicClient,
		RedirectURIs:            []string{"https://www.example-app.com/callback"},
		GrantTypes:              []string{constants.AuthorizationCodeGrantType},
		RequiresPKCE:            true,
		Scopes:                  []types.Scope{types.OpenIDScope, types.TokenIntrospectScope},
		ResponseTypes:           []string{constants.CodeResponseType, constants.IDTokenResponseType},
		ApplicationType:         constants.WebApplicationType,
		TokenEndpointAuthMethod: types.ClientSecretBasicTokenAuth,
	}
}

func createClientUpdateRequest() *clients.ClientUpdateRequest {
	return &clients.ClientUpdateRequest{
		Name:          "Test Client",
		Type:          types.PublicClient,
		RedirectURIs:  []string{"https://www.example-app.com/callback", "myapp://callback"},
		GrantTypes:    []string{constants.AuthorizationCodeGrantType},
		Scopes:        []types.Scope{types.OpenIDScope, types.TokenIntrospectScope},
		ResponseTypes: []string{constants.CodeResponseType, constants.IDTokenResponseType},
	}
}

func createClient() *clients.Client {
	return &clients.Client{
		Name:          "Test Client",
		Type:          types.PublicClient,
		RedirectURIs:  []string{"https://www.example-app.com/callback", "myapp://callback"},
		GrantTypes:    []string{constants.AuthorizationCodeGrantType},
		RequiresPKCE:  true,
		Scopes:        []types.Scope{types.OpenIDScope},
		ResponseTypes: []string{constants.CodeResponseType, constants.IDTokenResponseType},
	}
}
