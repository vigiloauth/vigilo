package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	audits "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mockAudit "github.com/vigiloauth/vigilo/v2/internal/mocks/audit"
	mockLogin "github.com/vigiloauth/vigilo/v2/internal/mocks/login"
	mockToken "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	mockUser "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
	service "github.com/vigiloauth/vigilo/v2/internal/service/crypto"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

const (
	testRequestID    string = "req-1234"
	testUsername     string = "username"
	testPassword1    string = "pas$2W_Ord"
	testEmail        string = "john.doe@mail.com"
	testUserID       string = "user-1234"
	testIPAddress    string = "127.0.01"
	testUserAgent    string = "user-agent/1.1"
	testAccessToken  string = "access_token"
	testRefreshToken string = "refresh_token"
)

func TestUserAuthenticator_AuthenticateUser(t *testing.T) {
	tests := []struct {
		name         string
		wantErr      bool
		expectedErr  string
		request      *users.UserLoginRequest
		repo         *mockUser.MockUserRepository
		loginService *mockLogin.MockLoginAttemptService
		auditLogger  *mockAudit.MockAuditLogger
		tokenIssuer  *mockToken.MockTokenIssuer
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			request:     &users.UserLoginRequest{Username: testUsername, Password: testPassword1},
			repo: &mockUser.MockUserRepository{
				GetUserByUsernameFunc: func(ctx context.Context, username string) (*users.User, error) {
					crypto := service.NewCryptographer()
					hashedPassword, _ := crypto.HashString(testPassword1)
					return &users.User{
						AccountLocked:     false,
						ID:                testUserID,
						PreferredUsername: testUsername,
						Password:          hashedPassword,
					}, nil
				},
				UpdateUserFunc: func(ctx context.Context, user *users.User) error { return nil },
			},
			loginService: &mockLogin.MockLoginAttemptService{
				SaveLoginAttemptFunc: func(ctx context.Context, attempt *users.UserLoginAttempt) error { return nil },
			},
			auditLogger: &mockAudit.MockAuditLogger{
				StoreEventFunc: func(ctx context.Context, eventType audits.EventType, success bool, action audits.ActionType, method audits.MethodType, err error) {
				},
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return testAccessToken, testRefreshToken, nil
				},
			},
		},
		{
			name:        "Internal error is returned when issuing tokens",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			request:     &users.UserLoginRequest{Username: testUsername, Password: testPassword1},
			repo: &mockUser.MockUserRepository{
				GetUserByUsernameFunc: func(ctx context.Context, username string) (*users.User, error) {
					crypto := service.NewCryptographer()
					hashedPassword, _ := crypto.HashString(testPassword1)
					return &users.User{
						AccountLocked:     false,
						ID:                testUserID,
						PreferredUsername: testUsername,
						Password:          hashedPassword,
					}, nil
				},
				UpdateUserFunc: func(ctx context.Context, user *users.User) error { return nil },
			},
			loginService: &mockLogin.MockLoginAttemptService{
				SaveLoginAttemptFunc: func(ctx context.Context, attempt *users.UserLoginAttempt) error { return nil },
				HandleFailedLoginAttemptFunc: func(ctx context.Context, user *users.User, attempt *users.UserLoginAttempt) error {
					return nil
				},
			},
			auditLogger: &mockAudit.MockAuditLogger{
				StoreEventFunc: func(ctx context.Context, eventType audits.EventType, success bool, action audits.ActionType, method audits.MethodType, err error) {
				},
			},
			tokenIssuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return "", "", errors.NewInternalServerError("failed to issue tokens")
				},
			},
		},
		{
			name:        "Account locked error is returned when the user's account is locked",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeAccountLocked],
			request:     &users.UserLoginRequest{Username: testUsername, Password: testPassword1},
			repo: &mockUser.MockUserRepository{
				GetUserByUsernameFunc: func(ctx context.Context, username string) (*users.User, error) {
					return &users.User{AccountLocked: true, ID: testUserID}, nil
				},
			},
			loginService: &mockLogin.MockLoginAttemptService{
				HandleFailedLoginAttemptFunc: func(ctx context.Context, user *users.User, attempt *users.UserLoginAttempt) error {
					return nil
				},
			},
			auditLogger: &mockAudit.MockAuditLogger{
				StoreEventFunc: func(ctx context.Context, eventType audits.EventType, success bool, action audits.ActionType, method audits.MethodType, err error) {
				},
			},
		},
		{
			name:        "Invalid credentials error is returned when the user does not exist",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInvalidCredentials],
			request:     &users.UserLoginRequest{Username: testUsername},
			repo: &mockUser.MockUserRepository{
				GetUserByUsernameFunc: func(ctx context.Context, username string) (*users.User, error) {
					return nil, errors.New(errors.ErrCodeUserNotFound, "user not found")
				},
			},
			auditLogger: &mockAudit.MockAuditLogger{
				StoreEventFunc: func(ctx context.Context, eventType audits.EventType, success bool, action audits.ActionType, method audits.MethodType, err error) {
				},
			},
		},
		{
			name:        "Invalid credentials error is returned when passwords don't match",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInvalidCredentials],
			request:     &users.UserLoginRequest{Username: testUsername, Password: testPassword1},
			repo: &mockUser.MockUserRepository{
				GetUserByUsernameFunc: func(ctx context.Context, username string) (*users.User, error) {
					return &users.User{
						AccountLocked:     false,
						ID:                testUserID,
						PreferredUsername: testUsername,
						Password:          testPassword1,
					}, nil
				},
			},
			loginService: &mockLogin.MockLoginAttemptService{
				HandleFailedLoginAttemptFunc: func(ctx context.Context, user *users.User, attempt *users.UserLoginAttempt) error {
					return nil
				},
			},
			auditLogger: &mockAudit.MockAuditLogger{
				StoreEventFunc: func(ctx context.Context, eventType audits.EventType, success bool, action audits.ActionType, method audits.MethodType, err error) {
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, testRequestID)
			ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyIPAddress, testIPAddress)
			ctx = utils.AddKeyValueToContext(ctx, constants.ContextKeyUserAgent, testUserAgent)

			service := NewUserAuthenticator(test.repo, test.auditLogger, test.loginService, test.tokenIssuer)
			resp, err := service.AuthenticateUser(ctx, test.request)

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to be equal")
				assert.Nil(t, resp, "Expected response to be nil but got: %v", resp)
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, resp, "Expected response to not be nil")
			}
		})
	}
}
