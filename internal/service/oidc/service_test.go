package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/authorization"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

func TestOIDCService_GetUserInfo(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name   string
			scopes string
		}{
			{
				name:   "Test with all requested scopes",
				scopes: fmt.Sprintf("%s %s %s %s %s %s", types.OpenIDScope, types.UserProfileScope, types.UserEmailScope, types.UserPhoneScope, types.UserAddressScope, types.UserOfflineAccessScope),
			},
			{
				name:   "Test with profile scope only",
				scopes: fmt.Sprintf("%s %s", types.OpenIDScope, types.UserProfileScope),
			},
			{
				name:   "Test with email scope only",
				scopes: fmt.Sprintf("%s %s", types.OpenIDScope, types.UserEmailScope),
			},
			{
				name:   "Test with phone scope only",
				scopes: fmt.Sprintf("%s %s", types.OpenIDScope, types.UserPhoneScope),
			},
			{
				name:   "Test with address scope only",
				scopes: fmt.Sprintf("%s %s", types.OpenIDScope, types.UserAddressScope),
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				expectedUser := getUser()
				authzService := &mocks.MockAuthorizationService{
					AuthorizeUserInfoRequestFunc: func(ctx context.Context, accessTokenClaims *token.TokenClaims) (*user.User, error) {
						return expectedUser, nil
					},
				}

				service := NewOIDCService(authzService)
				accessTokenClaims := &token.TokenClaims{
					Scopes: types.CombineScopes(types.Scope(test.scopes)),
				}

				userInfoResponse, err := service.GetUserInfo(context.Background(), accessTokenClaims)

				require.NoError(t, err, "Expected no error when retrieving user info")
				assert.NotNil(t, userInfoResponse, "Expected user info response to be non-nil")

				assert.Equal(t, expectedUser.ID, userInfoResponse.Sub, "Expected user ID in response to match expected user ID")
			})
		}
	})

	t.Run("Error is returned when the scopes are invalid", func(t *testing.T) {
		authzService := &mocks.MockAuthorizationService{
			AuthorizeUserInfoRequestFunc: func(ctx context.Context, accessTokenClaims *token.TokenClaims) (*user.User, error) {
				return nil, fmt.Errorf("invalid scopes")
			},
		}

		service := NewOIDCService(authzService)
		accessTokenClaims := &token.TokenClaims{}

		userInfoResponse, err := service.GetUserInfo(context.Background(), accessTokenClaims)

		require.Error(t, err, "Expected an error when retrieving user info with invalid scopes")
		assert.Nil(t, userInfoResponse, "Expected user info response to be nil when an error occurs")
	})
}

func getUser() *user.User {
	return &user.User{
		ID:                "12345",
		PreferredUsername: "john.doe",
		Name:              "John Mary Doe",
		GivenName:         "John",
		MiddleName:        "Mary",
		FamilyName:        "Doe",
		Email:             "john.doe@mail.com",
		PhoneNumber:       "+1234567890",
		Birthdate:         "1990-01-01",
		Gender:            "male",
		Address: &user.UserAddress{
			Formatted:     "123 Main St, Anytown, Anystate, 12345, Countryland",
			StreetAddress: "123 Main St",
			Locality:      "Anytown",
			Region:        "Anystate",
			PostalCode:    "12345",
			Country:       "Countryland",
		},
		UpdatedAt:           time.Now(),
		EmailVerified:       true,
		PhoneNumberVerified: true,
		AccountLocked:       false,
	}
}
