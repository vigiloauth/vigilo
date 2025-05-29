package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/authzcode"
)

func TestAuthorizationCodeIssuer_IssueAuthorizationCode(t *testing.T) {
	tests := []struct {
		name              string
		wantErr           bool
		expectedErrorCode string
		request           *client.ClientAuthorizationRequest
		creator           *mocks.MockAuthorizationCodeCreator
	}{
		{
			name:              "Success",
			wantErr:           false,
			expectedErrorCode: "",
			request:           createClientAuthorizationRequest(false),
			creator: &mocks.MockAuthorizationCodeCreator{
				GenerateAuthorizationCodeFunc: func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
					return "test-code", nil
				},
			},
		},
		{
			name:              "Internal error generating authorization code",
			wantErr:           true,
			expectedErrorCode: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			request:           createClientAuthorizationRequest(false),
			creator: &mocks.MockAuthorizationCodeCreator{
				GenerateAuthorizationCodeFunc: func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
					return "", errors.NewInternalServerError("")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			sut := NewAuthorizationCodeIssuer(
				test.creator,
			)

			code, err := sut.IssueAuthorizationCode(ctx, test.request)

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErrorCode, errors.SystemErrorCode(err), "Expected error code does not match")
				assert.Empty(t, code, "Expected empty code on error")
			} else {
				require.NoError(t, err, "Expected no error but got one")
				assert.NotEmpty(t, code, "Expected a non-empty code")
			}
		})
	}
}
