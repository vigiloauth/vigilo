package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	audit "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	emails "github.com/vigiloauth/vigilo/v2/internal/domain/email"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"

	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mockAudit "github.com/vigiloauth/vigilo/v2/internal/mocks/audit"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/crypto"
	mockEmails "github.com/vigiloauth/vigilo/v2/internal/mocks/email"
	mockToken "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	mockUser "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

func TestUserCreator_CreateUser(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		user        *users.User
		repo        *mockUser.MockUserRepository
		issuer      *mockToken.MockTokenIssuer
		audit       *mockAudit.MockAuditLogger
		email       *mockEmails.MockEmailService
		crypto      *mocks.MockCryptographer
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			user:        createNewUser(),
			repo: &mockUser.MockUserRepository{
				AddUserFunc: func(ctx context.Context, user *users.User) error {
					return nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
				HashStringFunc: func(plainStr string) (string, error) {
					return "hashed-password", nil
				},
			},
			issuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return "accessToken", "verificationCode", nil
				},
			},
			email: &mockEmails.MockEmailService{
				SendEmailFunc: func(ctx context.Context, request *emails.EmailRequest) error {
					return nil
				},
			},
			audit: &mockAudit.MockAuditLogger{
				StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {

				},
			},
		},
		{
			name:        "Duplicate user error is returned when user already exists",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeDuplicateUser],
			user:        createNewUser(),
			repo: &mockUser.MockUserRepository{
				AddUserFunc: func(ctx context.Context, user *users.User) error {
					return errors.New(errors.ErrCodeDuplicateUser, "duplicate user")
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
				HashStringFunc: func(plainStr string) (string, error) {
					return "hashed-password", nil
				},
			},
			audit: &mockAudit.MockAuditLogger{
				StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {

				},
			},
		},
		{
			name:        "Internal server error is returned when generating access token and verification code",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			user:        createNewUser(),
			repo: &mockUser.MockUserRepository{
				AddUserFunc: func(ctx context.Context, user *users.User) error {
					return nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
				HashStringFunc: func(plainStr string) (string, error) {
					return "hashed-password", nil
				},
			},
			issuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return "", "", errors.NewInternalServerError()
				},
			},
			audit: &mockAudit.MockAuditLogger{
				StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {

				},
			},
		},
		{
			name:        "Email delivery failed error is returned when sending email verification",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeEmailDeliveryFailed],
			user:        createNewUser(),
			repo: &mockUser.MockUserRepository{
				AddUserFunc: func(ctx context.Context, user *users.User) error {
					return nil
				},
			},
			crypto: &mocks.MockCryptographer{
				GenerateRandomStringFunc: func(length int) (string, error) {
					return "random-string", nil
				},
				HashStringFunc: func(plainStr string) (string, error) {
					return "hashed-password", nil
				},
			},
			issuer: &mockToken.MockTokenIssuer{
				IssueTokenPairFunc: func(ctx context.Context, subject, audience string, scopes types.Scope, roles, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
					return "token", "token", nil
				},
			},
			email: &mockEmails.MockEmailService{
				SendEmailFunc: func(ctx context.Context, request *emails.EmailRequest) error {
					return errors.New(errors.ErrCodeEmailDeliveryFailed, "failed to deliver email")
				},
			},
			audit: &mockAudit.MockAuditLogger{
				StoreEventFunc: func(ctx context.Context, eventType audit.EventType, success bool, action audit.ActionType, method audit.MethodType, err error) {

				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewUserCreator(test.repo, test.issuer, test.audit, test.email, test.crypto)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			res, err := sut.CreateUser(ctx, test.user)

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to match")
				assert.Nil(t, res, "Expected result to not be nil")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, res, "Expected the result to not be nil")
			}
		})
	}
}

func createNewUser() *users.User {
	user := users.NewUser(testUsername, testEmail, testPassword1)
	user.Address = users.NewUserAddress("123 Main", "Springfield", "IL", "012345", "USA")
	user.Roles = []string{constants.AdminRole}
	return user
}
