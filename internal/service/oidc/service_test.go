package service

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/authorization"
)

func TestOIDCService_GetUserInfo(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		tests := []struct {
			name   string
			scopes string
		}{
			{
				name:   "Test with all requested scopes",
				scopes: fmt.Sprintf("%s %s %s %s %s %s", constants.OIDC, constants.UserProfile, constants.UserEmail, constants.UserPhone, constants.UserAddress, constants.UserOfflineAccess),
			},
			{
				name:   "Test with profile scope only",
				scopes: fmt.Sprintf("%s %s", constants.OIDC, constants.UserProfile),
			},
			{
				name:   "Test with email scope only",
				scopes: fmt.Sprintf("%s %s", constants.OIDC, constants.UserEmail),
			},
			{
				name:   "Test with phone scope only",
				scopes: fmt.Sprintf("%s %s", constants.OIDC, constants.UserPhone),
			},
			{
				name:   "Test with address scope only",
				scopes: fmt.Sprintf("%s %s", constants.OIDC, constants.UserAddress),
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				expectedUser := getUser(test.scopes)
				authzService := &mocks.MockAuthorizationService{
					AuthorizeUserInfoRequestFunc: func(ctx context.Context, accessTokenClaims *token.TokenClaims, r *http.Request) (*user.User, error) {
						return expectedUser, nil
					},
				}

				service := NewOIDCService(authzService)
				accessTokenClaims := &token.TokenClaims{
					Scopes: test.scopes,
				}

				userInfoResponse, err := service.GetUserInfo(context.Background(), accessTokenClaims, &http.Request{})

				assert.NoError(t, err, "Expected no error when retrieving user info")
				assert.NotNil(t, userInfoResponse, "Expected user info response to be non-nil")

				expectedScopes := strings.Split(test.scopes, " ")
				assert.Equal(t, expectedUser.Scopes, expectedScopes, "Expected scopes in user info response to match requested scopes")
				assert.Equal(t, expectedUser.ID, userInfoResponse.Sub, "Expected user ID in response to match expected user ID")
			})
		}
	})

	t.Run("Error is returned when the scopes are invalid", func(t *testing.T) {
		authzService := &mocks.MockAuthorizationService{
			AuthorizeUserInfoRequestFunc: func(ctx context.Context, accessTokenClaims *token.TokenClaims, r *http.Request) (*user.User, error) {
				return nil, fmt.Errorf("invalid scopes")
			},
		}

		service := NewOIDCService(authzService)
		accessTokenClaims := &token.TokenClaims{}

		userInfoResponse, err := service.GetUserInfo(context.Background(), accessTokenClaims, &http.Request{})

		assert.Error(t, err, "Expected an error when retrieving user info with invalid scopes")
		assert.Nil(t, userInfoResponse, "Expected user info response to be nil when an error occurs")
	})
}

func getUser(scopes string) *user.User {
	return &user.User{
		ID:          "12345",
		Username:    "john.doe",
		FullName:    "John Mary Doe",
		FirstName:   "John",
		MiddleName:  "Mary",
		FamilyName:  "Doe",
		Email:       "john.doe@mail.com",
		PhoneNumber: "+1234567890",
		Birthdate:   "1990-01-01",
		Gender:      "male",
		Address: &user.UserAddress{
			Formatted:     "123 Main St, Anytown, Anystate, 12345, Countryland",
			StreetAddress: "123 Main St",
			Locality:      "Anytown",
			Region:        "Anystate",
			PostalCode:    "12345",
			Country:       "Countryland",
		},
		UpdatedAt:           time.Now(),
		Scopes:              strings.Split(scopes, " "),
		EmailVerified:       true,
		PhoneNumberVerified: true,
		AccountLocked:       false,
	}
}
