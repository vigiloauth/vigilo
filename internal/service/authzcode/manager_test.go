package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/authzcode"
)

func TestAuthorizationCodeManager_RevokeAuthorizationCode(t *testing.T) {
	tests := []struct {
		name            string
		wantErr         bool
		expectedErrCode string
		repo            *mocks.MockAuthorizationCodeRepository
	}{
		{
			name:            "Successful Revocation",
			wantErr:         false,
			expectedErrCode: "",
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return &domain.AuthorizationCodeData{Used: false}, nil
				},
				UpdateAuthorizationCodeFunc: func(ctx context.Context, code string, data *domain.AuthorizationCodeData) error {
					return nil
				},
			},
		},
		{
			name:            "Code not found error is returned",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeAuthorizationCodeNotFound],
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return nil, errors.New(errors.ErrCodeAuthorizationCodeNotFound, "authorization code not found")
				},
			},
		},
		{
			name:            "Internal server error is returned when updating code fails",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return &domain.AuthorizationCodeData{Used: false}, nil
				},
				UpdateAuthorizationCodeFunc: func(ctx context.Context, code string, data *domain.AuthorizationCodeData) error {
					return errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			sut := NewAuthorizationCodeManager(test.repo)

			err := sut.RevokeAuthorizationCode(ctx, "test-code")

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
			}
		})
	}
}

func TestAuthorizationCodeManager_UpdateAuthorizationCode(t *testing.T) {
	tests := []struct {
		name            string
		authData        *domain.AuthorizationCodeData
		wantErr         bool
		expectedErrCode string
		repo            *mocks.MockAuthorizationCodeRepository
	}{
		{
			name: "Successful Update",
			authData: &domain.AuthorizationCodeData{
				Code: "test-code",
				Used: false,
			},
			wantErr:         false,
			expectedErrCode: "",
			repo: &mocks.MockAuthorizationCodeRepository{
				UpdateAuthorizationCodeFunc: func(ctx context.Context, code string, data *domain.AuthorizationCodeData) error {
					return nil
				},
			},
		},
		{
			name: "Update Fails with Internal Server Error",
			authData: &domain.AuthorizationCodeData{
				Code: "test-code",
				Used: false,
			},
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repo: &mocks.MockAuthorizationCodeRepository{
				UpdateAuthorizationCodeFunc: func(ctx context.Context, code string, data *domain.AuthorizationCodeData) error {
					return errors.NewInternalServerError()
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			sut := NewAuthorizationCodeManager(test.repo)

			err := sut.UpdateAuthorizationCode(ctx, test.authData)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
			}
		})
	}
}

func TestAuthorizationCodeManager_GetAuthorizationCode(t *testing.T) {
	tests := []struct {
		name            string
		code            string
		wantErr         bool
		expectedErrCode string
		expectedData    *domain.AuthorizationCodeData
		repo            *mocks.MockAuthorizationCodeRepository
	}{
		{
			name:            "Successful Retrieval",
			code:            "test-code",
			wantErr:         false,
			expectedErrCode: "",
			expectedData: &domain.AuthorizationCodeData{
				Code: "test-code",
				Used: false,
			},
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return &domain.AuthorizationCodeData{Code: code, Used: false}, nil
				},
			},
		},
		{
			name:            "Code Not Found",
			code:            "invalid-code",
			wantErr:         true,
			expectedErrCode: errors.SystemErrorCodeMap[errors.ErrCodeAuthorizationCodeNotFound],
			expectedData:    nil,
			repo: &mocks.MockAuthorizationCodeRepository{
				GetAuthorizationCodeFunc: func(ctx context.Context, code string) (*domain.AuthorizationCodeData, error) {
					return nil, errors.New(errors.ErrCodeAuthorizationCodeNotFound, "authorization code not found")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			sut := NewAuthorizationCodeManager(test.repo)

			data, err := sut.GetAuthorizationCode(ctx, test.code)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrCode, errors.SystemErrorCode(err), "Expected error code does not match")
				assert.Nil(t, data, "Expected no data but got some")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.Equal(t, test.expectedData, data, "Expected data does not match")
			}
		})
	}
}
