package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mockAudit "github.com/vigiloauth/vigilo/v2/internal/mocks/audit"
	mockLogin "github.com/vigiloauth/vigilo/v2/internal/mocks/login"
	mockToken "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	mockUser "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

const (
	testRequestID string = "req-1234"
)

func TestUserAuthenticator_AuthenticateUser(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		request     *users.UserLoginRequest
		repo        *mockUser.MockUserRepository
		loginRepo   *mockLogin.MockLoginAttemptRepository
		tokenIssuer *mockToken.MockTokenIssuer
		auditLogger *mockAudit.MockAuditLogger
	}{}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)
			ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyIPAddress, testIPAddress)
			ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserAgent, testUserAgent)
			service := NewUserAuthenticator(test.repo, test.auditLogger, test.loginRepo, test.tokenIssuer)

			resp, err := service.AuthenticateUser(ctx, test.request)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to be equal")
				assert.Nil(t, resp, "Expected response to be nil but got: %v", resp)
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, resp, "Expected response to not be nil")
				assert.NotEmpty(t, resp.AccessToken, "Expected access token to not be empty")
				assert.NotEmpty(t, resp.RefreshToken, "Expected refresh token to not be empty")
			}
		})
	}
}

func TestUserAuthenticator_HandleFailedAuthenticationAttempt(t *testing.T) {}
