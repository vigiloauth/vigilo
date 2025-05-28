package service

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/crypto"
	tokens "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
	userMocks "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
)

const (
	requestID  string = "req"
	userID     string = "user-1234"
	username   string = "john.doe"
	firstName  string = "john"
	middleName string = "smith"
	lastName   string = "doe"
	email      string = "john.doe@mail.com"
)

func TestUserManager_GetUserByUsername(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		expectedRes *users.User
		repo        *userMocks.MockUserRepository
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			expectedRes: &users.User{
				ID:                userID,
				PreferredUsername: username,
				Name:              firstName,
				MiddleName:        middleName,
				FamilyName:        lastName,
			},
			repo: &userMocks.MockUserRepository{
				GetUserByUsernameFunc: func(ctx context.Context, username string) (*users.User, error) {
					return &users.User{
						ID:                userID,
						PreferredUsername: username,
						Name:              firstName,
						MiddleName:        middleName,
						FamilyName:        lastName,
					}, nil
				},
			},
		},
		{
			name:        "User not found error is returned",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUserNotFound],
			expectedRes: nil,
			repo: &userMocks.MockUserRepository{
				GetUserByUsernameFunc: func(ctx context.Context, username string) (*users.User, error) {
					return nil, errors.New(errors.ErrCodeUserNotFound, "user not found")
				},
			},
		},
		{
			name:        "Internal server error is returned on DB failure",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			expectedRes: nil,
			repo: &userMocks.MockUserRepository{
				GetUserByUsernameFunc: func(ctx context.Context, username string) (*users.User, error) {
					return nil, errors.NewInternalServerError("")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewUserManager(test.repo, nil, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			res, err := sut.GetUserByUsername(ctx, username)

			if test.wantErr {
				require.Error(t, err)
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err))
				assert.Nil(t, res)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, res)
				assert.Equal(t, test.expectedRes.ID, res.ID)
				assert.Equal(t, test.expectedRes.PreferredUsername, res.PreferredUsername, "Expected usernames to be equal")
				assert.Equal(t, test.expectedRes.MiddleName, res.MiddleName, "Expected middle names to be equal")
				assert.Equal(t, test.expectedRes.FamilyName, res.FamilyName, "Expected family names to be equal")
				assert.Equal(t, test.expectedRes.Name, res.Name, "Expected names to be equal")
			}
		})
	}
}

func TestUserManager_GetUserByID(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		expectedRes *users.User
		repo        *userMocks.MockUserRepository
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			expectedRes: &users.User{
				ID:                userID,
				PreferredUsername: username,
				Name:              firstName,
				MiddleName:        middleName,
				FamilyName:        lastName,
			},
			repo: &userMocks.MockUserRepository{
				GetUserByIDFunc: func(ctx context.Context, username string) (*users.User, error) {
					return &users.User{
						ID:                userID,
						PreferredUsername: username,
						Name:              firstName,
						MiddleName:        middleName,
						FamilyName:        lastName,
					}, nil
				},
			},
		},
		{
			name:        "User not found error is returned",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUserNotFound],
			expectedRes: nil,
			repo: &userMocks.MockUserRepository{
				GetUserByIDFunc: func(ctx context.Context, username string) (*users.User, error) {
					return nil, errors.New(errors.ErrCodeUserNotFound, "user not found")
				},
			},
		},
		{
			name:        "Internal server error is returned on DB failure",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			expectedRes: nil,
			repo: &userMocks.MockUserRepository{
				GetUserByIDFunc: func(ctx context.Context, username string) (*users.User, error) {
					return nil, errors.NewInternalServerError("")
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sut := NewUserManager(test.repo, nil, nil, nil)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			res, err := sut.GetUserByID(ctx, userID)

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to match")
				assert.Nil(t, res, "Expected result to not be nil")
			} else {
				require.NoError(t, err)
				assert.NotNil(t, res)
				assert.Equal(t, test.expectedRes.ID, res.ID)
				assert.Equal(t, test.expectedRes.MiddleName, res.MiddleName, "Expected middle names to be equal")
				assert.Equal(t, test.expectedRes.FamilyName, res.FamilyName, "Expected family names to be equal")
				assert.Equal(t, test.expectedRes.Name, res.Name, "Expected names to be equal")
			}
		})
	}
}

func TestUserManager_DeleteUnverifiedUsers(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		repo        *userMocks.MockUserRepository
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			repo: &userMocks.MockUserRepository{
				FindUnverifiedUsersOlderThanWeekFunc: func(ctx context.Context) ([]*users.User, error) {
					return []*users.User{{ID: userID}}, nil
				},
				DeleteUserByIDFunc: func(ctx context.Context, userID string) error {
					return nil
				},
			},
		},
		{
			name:        "Internal error is returned on retrieval",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repo: &userMocks.MockUserRepository{
				FindUnverifiedUsersOlderThanWeekFunc: func(ctx context.Context) ([]*users.User, error) {
					return nil, errors.NewInternalServerError("")
				},
			},
		},
		{
			name:        "User not found by ID error is returned",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUserNotFound],
			repo: &userMocks.MockUserRepository{
				FindUnverifiedUsersOlderThanWeekFunc: func(ctx context.Context) ([]*users.User, error) {
					return []*users.User{{ID: userID}}, nil
				},
				DeleteUserByIDFunc: func(ctx context.Context, userID string) error {
					return errors.New(errors.ErrCodeUserNotFound, "user not found by ID")
				},
			},
		},
	}

	for _, test := range tests {
		sut := NewUserManager(test.repo, nil, nil, nil)
		ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

		err := sut.DeleteUnverifiedUsers(ctx)

		if test.wantErr {
			require.Error(t, err, "Expected an error but got none")
			assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to match")
		} else {
			require.NoError(t, err, "Expected no error but got: %v", err)
		}
	}
}

func TestUserManager_ResetPassword(t *testing.T) {
	tests := []struct {
		name        string
		wantErr     bool
		expectedErr string
		repo        *userMocks.MockUserRepository
		parser      *tokens.MockTokenParser
		manager     *tokens.MockTokenManager
		crypto      *mocks.MockCryptographer
	}{
		{
			name:        "Success",
			wantErr:     false,
			expectedErr: "",
			repo: &userMocks.MockUserRepository{
				GetUserByEmailFunc: func(ctx context.Context, email string) (*users.User, error) {
					return &users.User{
						ID:            userID,
						AccountLocked: true,
					}, nil
				},
				UpdateUserFunc: func(ctx context.Context, user *users.User) error {
					return nil
				},
			},
			crypto: &mocks.MockCryptographer{
				HashStringFunc: func(plainStr string) (string, error) {
					return hashedPassword, nil
				},
			},
			parser: &tokens.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*domain.TokenClaims, error) {
					return &domain.TokenClaims{
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
			name:        "Token parsing error returned when parsing reset token",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeTokenParsing],
			repo: &userMocks.MockUserRepository{
				GetUserByEmailFunc: func(ctx context.Context, email string) (*users.User, error) {
					return &users.User{
						ID:            userID,
						AccountLocked: true,
					}, nil
				},
			},
			crypto: &mocks.MockCryptographer{
				HashStringFunc: func(plainStr string) (string, error) {
					return hashedPassword, nil
				},
			},
			parser: &tokens.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*domain.TokenClaims, error) {
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
			name:        "Unauthorized error is returned when user ID doesn't match token subject",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUnauthorized],
			repo: &userMocks.MockUserRepository{
				GetUserByEmailFunc: func(ctx context.Context, email string) (*users.User, error) {
					return &users.User{
						ID:            userID,
						AccountLocked: true,
					}, nil
				},
			},
			crypto: &mocks.MockCryptographer{
				HashStringFunc: func(plainStr string) (string, error) {
					return hashedPassword, nil
				},
			},
			parser: &tokens.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*domain.TokenClaims, error) {
					return &domain.TokenClaims{
						StandardClaims: &jwt.StandardClaims{
							Subject: "invalid-user-ID",
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
			name:        "User not found error is returned when user does not exist",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeUserNotFound],
			repo: &userMocks.MockUserRepository{
				GetUserByEmailFunc: func(ctx context.Context, email string) (*users.User, error) {
					return nil, errors.New(errors.ErrCodeUserNotFound, "user not found")
				},
			},
			crypto: &mocks.MockCryptographer{
				HashStringFunc: func(plainStr string) (string, error) {
					return hashedPassword, nil
				},
			},
			manager: &tokens.MockTokenManager{
				BlacklistTokenFunc: func(ctx context.Context, token string) error {
					return nil
				},
			},
		},
		{
			name:        "Internal server error is returned when updating the user fails",
			wantErr:     true,
			expectedErr: errors.SystemErrorCodeMap[errors.ErrCodeInternalServerError],
			repo: &userMocks.MockUserRepository{
				GetUserByEmailFunc: func(ctx context.Context, email string) (*users.User, error) {
					return &users.User{
						ID:            userID,
						AccountLocked: true,
					}, nil
				},
				UpdateUserFunc: func(ctx context.Context, user *users.User) error {
					return errors.NewInternalServerError("")
				},
			},
			crypto: &mocks.MockCryptographer{
				HashStringFunc: func(plainStr string) (string, error) {
					return hashedPassword, nil
				},
			},
			parser: &tokens.MockTokenParser{
				ParseTokenFunc: func(ctx context.Context, tokenString string) (*domain.TokenClaims, error) {
					return &domain.TokenClaims{
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
			sut := NewUserManager(test.repo, test.parser, test.manager, test.crypto)
			ctx := context.WithValue(context.Background(), constants.ContextKeyRequestID, requestID)

			res, err := sut.ResetPassword(ctx, email, "newPassword", "resetToken")

			if test.wantErr {
				require.Error(t, err, "Expected an error but got none")
				assert.Equal(t, test.expectedErr, errors.SystemErrorCode(err), "Expected error codes to match")
			} else {
				require.NoError(t, err, "Expected no error but got: %v", err)
				assert.NotNil(t, res, "Expected result to not be nil")
			}
		})
	}
}
