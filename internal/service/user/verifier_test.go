package service

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	tokens "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	users "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
)

func TestUserVerifier_VerifyEmailAddress(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		repo        *users.MockUserRepository
		parser      *tokens.MockTokenParser
		validator   *tokens.MockTokenValidator
		manager     *tokens.MockTokenManager
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			repo: &users.MockUserRepository{
				GetUserByIDFunc: func(ctx context.Context, userID string) (*user.User, error) {
					return &user.User{
						ID:            userID,
						EmailVerified: false,
					}, nil
				},
				UpdateUserFunc: func(ctx context.Context, user *user.User) error {
					return nil
				},
			},
			validator: &tokens.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
			parser: &tokens.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
					return &token.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							Subject: userID,
						},
					}, nil
				},
			},
			manager: &tokens.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:        "Unauthorized error is returned when retrieving user by ID",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			repo: &users.MockUserRepository{
				GetUserByIDFunc: func(ctx context.Context, userID string) (*user.User, error) {
					return nil, errors.New(errors.ErrCodeUserNotFound, "user not found")
				},
			},
			manager: &tokens.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
			validator: &tokens.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
			parser: &tokens.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
					return &token.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							Subject: "invalidUserID",
						},
					}, nil
				},
			},
		},
		{
			name:        "Unauthorized error is returned when validating the verification code",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			repo: &users.MockUserRepository{
				GetUserByIDFunc: func(ctx context.Context, userID string) (*user.User, error) {
					return &user.User{
						ID:            userID,
						EmailVerified: false,
					}, nil
				},
			},
			validator: &tokens.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return errors.New(errors.ErrCodeExpiredToken, "expired token")
				},
			},
			manager: &tokens.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:        "Token parsing error is returned when parsing the token",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeTokenParsing],
			repo: &users.MockUserRepository{
				GetUserByIDFunc: func(ctx context.Context, userID string) (*user.User, error) {
					return &user.User{
						ID:            userID,
						EmailVerified: false,
					}, nil
				},
			},
			validator: &tokens.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
			parser: &tokens.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
					return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
				},
			},
			manager: &tokens.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:        "Internal server error is returned when updating the user",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repo: &users.MockUserRepository{
				GetUserByIDFunc: func(ctx context.Context, userID string) (*user.User, error) {
					return &user.User{
						ID:            userID,
						EmailVerified: false,
					}, nil
				},
				UpdateUserFunc: func(ctx context.Context, user *user.User) error {
					return errors.NewInternalServerError()
				},
			},
			validator: &tokens.MockTokenValidator{
				ValidateTokenFunc: func(ctx context.Context, tokenStr string) error {
					return nil
				},
			},
			parser: &tokens.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
					return &token.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							Subject: userID,
						},
					}, nil
				},
			},
			manager: &tokens.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewUserVerifier(test.repo, test.parser, test.validator, test.manager)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			err := sut.VerifyEmailAddress(ctx, "verificationCode")

			if test.wantErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to match")
			} else {
				assert.NoError(t, err, "Expected no error but got: %v", err)
			}
		})
	}
}
