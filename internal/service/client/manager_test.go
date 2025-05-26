package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	clientMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	cryptoMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/crypto"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

func TestClientManager_RegenerateClientSecret(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		repo            *clientMocks.MockClientRepository
		authenticator   *clientMocks.MockClientAuthenticator
		cryptographer   *cryptoMocks.MockCryptographer
	}{
		{
			name:            "Successful Regeneration",
			wantErr:         false,
			expectedErrCode: "",
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
					}, nil
				},
				UpdateClientFunc: func(ctx context.Context, client *client.Client) error {
					return nil
				},
			},
			authenticator: &clientMocks.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *client.ClientAuthenticationRequest) error {
					return nil
				},
			},
			cryptographer: &cryptoMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "new-secret", nil
				},
				HashStringFunc: func(secret string) (string, error) {
					return "hashed-new-secret", nil
				},
			},
		},
		{
			name:            "Invalid client error is returned when client is not confidential",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInvalidClient],
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:   clientID,
						Type: types.PublicClient,
					}, nil
				},
			},
		},
		{
			name:            "Unauthorized client error is returned when client authentication fails",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorizedClient],
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
					}, nil
				},
			},
			authenticator: &clientMocks.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *client.ClientAuthenticationRequest) error {
					return errors.New(errors.ErrCodeUnauthorizedClient, "invalid credentials")
				},
			},
		},
		{
			name:            "Internal server error is returned when generating new secret fails",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
					}, nil
				},
			},
			authenticator: &clientMocks.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *client.ClientAuthenticationRequest) error {
					return nil
				},
			},
			cryptographer: &cryptoMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "", errors.New(errors.ErrCodeRandomGenerationFailed, "failed to generate random string")
				},
			},
		},
		{
			name:            "Internal server error is returned when hashing the new secret",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
					}, nil
				},
			},
			authenticator: &clientMocks.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *client.ClientAuthenticationRequest) error {
					return nil
				},
			},
			cryptographer: &cryptoMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "secret", nil
				},
				HashStringFunc: func(secret string) (string, error) {
					return "", errors.New(errors.ErrCodeHashingFailed, "failed to hash string")
				},
			},
		},
		{
			name:            "Unexpected error is returned when updating the client",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
					}, nil
				},
				UpdateClientFunc: func(ctx context.Context, client *client.Client) error {
					return errors.New(errors.ErrCodeInternalServerError, "unexpected error while updating client")
				},
			},
			authenticator: &clientMocks.MockClientAuthenticator{
				AuthenticateClientFunc: func(ctx context.Context, req *client.ClientAuthenticationRequest) error {
					return nil
				},
			},
			cryptographer: &cryptoMocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "new-secret", nil
				},
				HashStringFunc: func(plainStr string) (string, error) {
					return "hashed-new-secret", nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewClientManager(test.repo, nil, test.authenticator, test.cryptographer)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			res, err := sut.RegenerateClientSecret(ctx, clientID)

			if test.wantErr {
				assert.Error(t, err, "Expected error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
				assert.Nil(t, res, "Expected nil response on error")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.NotNil(t, res, "Expected a response but got nil")
			}
		})
	}
}

func TestClientManager_GetClientByID(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		repo            *clientMocks.MockClientRepository
	}{
		{
			name:            "Successful retrieval of client by ID",
			wantErr:         false,
			expectedErrCode: "",
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
					}, nil
				},
			},
		},
		{
			name:            "Client not found error is returned",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeClientNotFound],
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return nil, errors.New(errors.ErrCodeClientNotFound, "client not found")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewClientManager(test.repo, nil, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			res, err := sut.GetClientByID(ctx, clientID)
			if test.wantErr {
				assert.Error(t, err, "Expected error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
				assert.Nil(t, res, "Expected nil response on error")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.NotNil(t, res, "Expected a response but got nil")
			}
		})
	}
}

func TestClientManager_GetClientInformation(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		validator       *clientMocks.MockClientValidator
		repo            *clientMocks.MockClientRepository
	}{
		{
			name:            "Successful retrieval of client information",
			wantErr:         false,
			expectedErrCode: "",
			validator: &clientMocks.MockClientValidator{
				ValidateClientAndRegistrationAccessTokenFunc: func(ctx context.Context, clientID, registrationAccessToken string) error {
					return nil
				},
			},
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
					}, nil
				},
			},
		},
		{
			name:            "Unauthorized error is returned when client validation fails",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			validator: &clientMocks.MockClientValidator{
				ValidateClientAndRegistrationAccessTokenFunc: func(ctx context.Context, clientID, registrationAccessToken string) error {
					return errors.New(errors.ErrCodeUnauthorized, "invalid client or access token")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewClientManager(test.repo, test.validator, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)
			res, err := sut.GetClientInformation(ctx, clientID, "accessToken")

			if test.wantErr {
				assert.Error(t, err, "Expected error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
				assert.Nil(t, res, "Expected nil response on error")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.NotNil(t, res, "Expected a response but got nil")
			}
		})
	}
}

func TestClientManager_UpdateClientInformation(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		request         *client.ClientUpdateRequest
		validator       *clientMocks.MockClientValidator
		repo            *clientMocks.MockClientRepository
	}{
		{
			name:            "Successful update of client information",
			wantErr:         false,
			expectedErrCode: "",
			request: &client.ClientUpdateRequest{
				Name:   "Updated Client Name",
				Secret: secret,
				ID:     clientID,
			},
			validator: &clientMocks.MockClientValidator{
				ValidateUpdateRequestFunc: func(ctx context.Context, req *client.ClientUpdateRequest) error {
					return nil
				},
				ValidateClientAndRegistrationAccessTokenFunc: func(ctx context.Context, clientID, registrationAccessToken string) error {
					return nil
				},
			},
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
					}, nil
				},
				UpdateClientFunc: func(ctx context.Context, client *client.Client) error {
					return nil
				},
			},
		},
		{
			name:            "Unauthorized error is returned when client validation fails",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			request: &client.ClientUpdateRequest{
				Name:   "Updated Client Name",
				Secret: secret,
				ID:     clientID,
			},
			validator: &clientMocks.MockClientValidator{
				ValidateUpdateRequestFunc: func(ctx context.Context, req *client.ClientUpdateRequest) error {
					return nil
				},
				ValidateClientAndRegistrationAccessTokenFunc: func(ctx context.Context, clientID, registrationAccessToken string) error {
					return errors.New(errors.ErrCodeUnauthorized, "invalid client or access token")
				},
			},
		},
		{
			name:            "Invalid client metadata error is returned when validating the update request",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInvalidClientMetadata],
			request: &client.ClientUpdateRequest{
				Name:   "",
				Secret: secret,
				ID:     clientID,
			},
			validator: &clientMocks.MockClientValidator{
				ValidateUpdateRequestFunc: func(ctx context.Context, req *client.ClientUpdateRequest) error {
					return errors.New(errors.ErrCodeInvalidClientMetadata, "client name cannot be empty")
				},
			},
		},
		{
			name:            "Unauthorized error is returned when client secrets don't match",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			request: &client.ClientUpdateRequest{
				Name:   "Updated Client Name",
				Secret: secret,
				ID:     clientID,
			},
			validator: &clientMocks.MockClientValidator{
				ValidateUpdateRequestFunc: func(ctx context.Context, req *client.ClientUpdateRequest) error {
					return nil
				},
				ValidateClientAndRegistrationAccessTokenFunc: func(ctx context.Context, clientID, registrationAccessToken string) error {
					return nil
				},
			},
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: "invalid secret",
						Type:   types.ConfidentialClient,
					}, nil
				},
			},
		},
		{
			name:            "Internal server error is returned when updating client fails",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			request: &client.ClientUpdateRequest{
				Name:   "Updated Client Name",
				Secret: secret,
				ID:     clientID,
			},
			validator: &clientMocks.MockClientValidator{
				ValidateUpdateRequestFunc: func(ctx context.Context, req *client.ClientUpdateRequest) error {
					return nil
				},
				ValidateClientAndRegistrationAccessTokenFunc: func(ctx context.Context, clientID, registrationAccessToken string) error {
					return nil
				},
			},
			repo: &clientMocks.MockClientRepository{
				GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
					return &client.Client{
						ID:     clientID,
						Secret: secret,
						Type:   types.ConfidentialClient,
					}, nil
				},
				UpdateClientFunc: func(ctx context.Context, client *client.Client) error {
					return errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewClientManager(test.repo, test.validator, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)
			res, err := sut.UpdateClientInformation(ctx, clientID, "accessToken", test.request)

			if test.wantErr {
				assert.Error(t, err, "Expected error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
				assert.Nil(t, res, "Expected nil response on error")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.NotNil(t, res, "Expected a response but got nil")
			}
		})
	}
}

func TestClientManager_DeleteClientInformation(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		validator       *clientMocks.MockClientValidator
		repo            *clientMocks.MockClientRepository
	}{
		{
			name:            "Successful deletion of client information",
			wantErr:         false,
			expectedErrCode: "",
			validator: &clientMocks.MockClientValidator{
				ValidateClientAndRegistrationAccessTokenFunc: func(ctx context.Context, clientID, registrationAccessToken string) error {
					return nil
				},
			},
			repo: &clientMocks.MockClientRepository{
				DeleteClientByIDFunc: func(ctx context.Context, clientID string) error {
					return nil
				},
			},
		},
		{
			name:            "Unauthorized error is returned when client validation fails",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			validator: &clientMocks.MockClientValidator{
				ValidateClientAndRegistrationAccessTokenFunc: func(ctx context.Context, clientID, registrationAccessToken string) error {
					return errors.New(errors.ErrCodeUnauthorized, "invalid client or access token")
				},
			},
		},
		{
			name:            "Internal server error is returned when deleting client fails",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			validator: &clientMocks.MockClientValidator{
				ValidateClientAndRegistrationAccessTokenFunc: func(ctx context.Context, clientID, registrationAccessToken string) error {
					return nil
				},
			},
			repo: &clientMocks.MockClientRepository{
				DeleteClientByIDFunc: func(ctx context.Context, clientID string) error {
					return errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewClientManager(test.repo, test.validator, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)

			err := sut.DeleteClientInformation(ctx, clientID, "accessToken")

			if test.wantErr {
				assert.Error(t, err, "Expected error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
			}
		})
	}
}
