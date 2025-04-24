package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/internal/crypto"
	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	mAuthzRepository "github.com/vigiloauth/vigilo/internal/mocks/authzcode"
	mClientService "github.com/vigiloauth/vigilo/internal/mocks/client"
	mUserService "github.com/vigiloauth/vigilo/internal/mocks/user"
)

const (
	testUserID         string = "testUserID"
	testUserPassword   string = "testPassword"
	testEmail          string = "testEmail"
	testClientName     string = "testClient"
	testClientID       string = "clientID"
	testClientSecret   string = "secret"
	testScope          string = "clients:manage"
	testRedirectURI    string = "http://localhost/callback"
	testCode           string = "12314324code"
	validCodeChallenge string = "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_"
)

func TestAuthorizationCodeService_GenerateAuthorizationCode(t *testing.T) {
	mockUserService := &mUserService.MockUserService{}
	mockClientService := &mClientService.MockClientService{}
	mockAuthzCodeRepo := &mAuthzRepository.MockAuthorizationCodeRepository{}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockUserService.GetUserByIDFunc = func(ctx context.Context, userID string) (*user.User, error) { return createTestUser(), nil }
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) { return createTestClient(), nil }
		mockClientService.ValidateClientRedirectURIFunc = func(redirectURI string, existingClient *client.Client) error { return nil }
		mockAuthzCodeRepo.StoreAuthorizationCodeFunc = func(ctx context.Context, code string, data *authz.AuthorizationCodeData, expiresAt time.Time) error {
			return nil
		}

		service := NewAuthorizationCodeService(mockAuthzCodeRepo, mockUserService, mockClientService)
		code, err := service.GenerateAuthorizationCode(ctx, createClientAuthorizationRequest())

		assert.NoError(t, err)
		assert.NotEqual(t, "", code)
	})

	t.Run("Error is returned when a database error occurs", func(t *testing.T) {
		mockUserService.GetUserByIDFunc = func(ctx context.Context, userID string) (*user.User, error) { return createTestUser(), nil }
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) { return createTestClient(), nil }
		mockClientService.ValidateClientRedirectURIFunc = func(redirectURI string, existingClient *client.Client) error { return nil }
		mockAuthzCodeRepo.StoreAuthorizationCodeFunc = func(ctx context.Context, code string, data *authz.AuthorizationCodeData, expiresAt time.Time) error {
			return errors.NewInternalServerError()
		}

		service := NewAuthorizationCodeService(mockAuthzCodeRepo, mockUserService, mockClientService)
		code, err := service.GenerateAuthorizationCode(ctx, createClientAuthorizationRequest())

		assert.Error(t, err)
		assert.Equal(t, "", code)
	})

	t.Run("Error is returned when the user does not exist with the given ID", func(t *testing.T) {
		mockUserService.GetUserByIDFunc = func(ctx context.Context, userID string) (*user.User, error) { return nil, nil }

		service := NewAuthorizationCodeService(mockAuthzCodeRepo, mockUserService, mockClientService)
		expected := errors.New(errors.ErrCodeUnauthorized, "invalid user ID: testU[REDACTED]")
		code, actual := service.GenerateAuthorizationCode(ctx, createClientAuthorizationRequest())

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
		assert.Equal(t, "", code)
	})

	t.Run("Error is returned when the client does not exist with the given ID", func(t *testing.T) {
		mockUserService.GetUserByIDFunc = func(ctx context.Context, userID string) (*user.User, error) { return createTestUser(), nil }
		mockClientService.GetClientByIDFunc = func(ctx context.Context, clientID string) (*client.Client, error) { return nil, nil }

		service := NewAuthorizationCodeService(mockAuthzCodeRepo, mockUserService, mockClientService)
		expected := errors.New(errors.ErrCodeUnauthorized, "invalid client ID")
		code, actual := service.GenerateAuthorizationCode(ctx, createClientAuthorizationRequest())

		assert.Error(t, actual)
		assert.Equal(t, expected.Error(), actual.Error())
		assert.Equal(t, "", code)
	})
}

func TestAuthorizationCodeService_ValidateAuthorizationCode(t *testing.T) {
	mockUserService := &mUserService.MockUserService{}
	mockClientService := &mClientService.MockClientService{}
	mockAuthzCodeRepo := &mAuthzRepository.MockAuthorizationCodeRepository{}
	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		mockAuthzCodeRepo.GetAuthorizationCodeFunc = func(ctx context.Context, code string) (*authz.AuthorizationCodeData, error) {
			return createAuthzCodeData(), nil
		}
		mockAuthzCodeRepo.DeleteAuthorizationCodeFunc = func(ctx context.Context, code string) error { return nil }
		mockAuthzCodeRepo.UpdateAuthorizationCodeFunc = func(ctx context.Context, code string, authData *authz.AuthorizationCodeData) error {
			return nil
		}

		service := NewAuthorizationCodeService(mockAuthzCodeRepo, mockUserService, mockClientService)
		data, err := service.ValidateAuthorizationCode(ctx, testCode, testClientID, testRedirectURI)

		assert.NotNil(t, data)
		assert.NoError(t, err)
	})

	t.Run("Error is returned when the authorization code is not found or expired", func(t *testing.T) {
		mockAuthzCodeRepo.GetAuthorizationCodeFunc = func(ctx context.Context, code string) (*authz.AuthorizationCodeData, error) {
			return nil, errors.NewInternalServerError()
		}

		service := NewAuthorizationCodeService(mockAuthzCodeRepo, mockUserService, mockClientService)
		code, actual := service.ValidateAuthorizationCode(ctx, testCode, testClientID, testRedirectURI)

		assert.Nil(t, code)
		assert.Error(t, actual)
		assert.Equal(t, "invalid authorization code", actual.Error())
	})

	t.Run("Error is returned when there is a client ID mismatch", func(t *testing.T) {
		mockAuthzCodeRepo.GetAuthorizationCodeFunc = func(ctx context.Context, code string) (*authz.AuthorizationCodeData, error) {
			return createAuthzCodeData(), nil
		}

		service := NewAuthorizationCodeService(mockAuthzCodeRepo, mockUserService, mockClientService)
		expected := "failed to validate authorization code: authorization code client ID and request client ID do no match"
		code, actual := service.ValidateAuthorizationCode(ctx, testCode, "invalidID", testRedirectURI)

		assert.Nil(t, code)
		assert.Error(t, actual)
		assert.Equal(t, expected, actual.Error())
	})

	t.Run("Error is returned when there is a redirectURI mismatch", func(t *testing.T) {
		mockAuthzCodeRepo.GetAuthorizationCodeFunc = func(ctx context.Context, code string) (*authz.AuthorizationCodeData, error) {
			return createAuthzCodeData(), nil
		}

		service := NewAuthorizationCodeService(mockAuthzCodeRepo, mockUserService, mockClientService)
		expected := "failed to validate authorization code: authorization code redirect URI and request redirect URI do no match"
		code, actual := service.ValidateAuthorizationCode(ctx, testCode, testClientID, "testRedirectURI")

		assert.Nil(t, code)
		assert.Error(t, actual)
		assert.Equal(t, expected, actual.Error())
	})
}

func TestAuthorizationCodeService_ValidatePKCE(t *testing.T) {
	codeVerifier := "validCodeVerifier123"
	codeChallenge := crypto.EncodeSHA256(codeVerifier)

	tests := []struct {
		name         string
		codeData     *authz.AuthorizationCodeData
		codeVerifier string
		wantErr      bool
		errMessage   string
	}{
		{
			name: "Successful validation for SHA-256 encryption",
			codeData: &authz.AuthorizationCodeData{
				CodeChallengeMethod: authz.S256,
				CodeChallenge:       codeChallenge,
			},
			codeVerifier: codeVerifier,
			wantErr:      false,
		},
		{
			name: "Successful validation for plain method",
			codeData: &authz.AuthorizationCodeData{
				CodeChallengeMethod: authz.Plain,
				CodeChallenge:       codeVerifier,
			},
			codeVerifier: codeVerifier,
			wantErr:      false,
		},
		{
			name: "Unsupported code challenge method",
			codeData: &authz.AuthorizationCodeData{
				CodeChallengeMethod: "unsupported",
				CodeChallenge:       codeChallenge,
			},
			codeVerifier: codeVerifier,
			wantErr:      true,
			errMessage:   "unsupported code challenge method",
		},
		{
			name: "Failed validation for SHA-256 encryption with invalid code verifier",
			codeData: &authz.AuthorizationCodeData{
				CodeChallengeMethod: authz.S256,
				CodeChallenge:       codeChallenge,
			},
			codeVerifier: "invalidCodeVerifier",
			wantErr:      true,
			errMessage:   "invalid code verifier",
		},
		{
			name: "Failed validation for plain method with mismatched code verifier",
			codeData: &authz.AuthorizationCodeData{
				CodeChallengeMethod: authz.Plain,
				CodeChallenge:       codeChallenge,
			},
			codeVerifier: "invalidCodeVerifier",
			wantErr:      true,
			errMessage:   "invalid code verifier",
		},
	}

	for _, test := range tests {
		service := NewAuthorizationCodeService(nil, nil, nil)
		err := service.ValidatePKCE(test.codeData, test.codeVerifier)

		if test.wantErr {
			assert.Error(t, err, fmt.Sprintf("expected an error for [%s]", test.name))
			assert.Contains(t, err.Error(), test.errMessage)
		} else {
			assert.NoError(t, err, fmt.Sprintf("expected no error for [%s]", test.name))
		}
	}
}

func createTestUser() *user.User {
	return user.NewUser(
		testUserID,
		testEmail,
		testUserPassword,
	)
}

func createTestClient() *client.Client {
	return &client.Client{
		Name:          testClientName,
		ID:            testClientID,
		Secret:        testClientSecret,
		Type:          client.Confidential,
		RedirectURIS:  []string{testRedirectURI},
		Scopes:        []string{constants.ClientManage, constants.ClientRead, constants.ClientWrite},
		ResponseTypes: []string{constants.CodeResponseType, constants.TokenResponseType},
		GrantTypes:    []string{constants.AuthorizationCode},
	}
}

func createAuthzCodeData() *authz.AuthorizationCodeData {
	return &authz.AuthorizationCodeData{
		UserID:      testUserID,
		ClientID:    testClientID,
		RedirectURI: testRedirectURI,
		Scope:       testScope,
		CreatedAt:   time.Now(),
	}
}

func createClientAuthorizationRequest() *client.ClientAuthorizationRequest {
	return &client.ClientAuthorizationRequest{
		ClientID:    testClientID,
		UserID:      testUserID,
		Scope:       testScope,
		RedirectURI: testRedirectURI,
		Client: &client.Client{
			Type:          client.Public,
			ResponseTypes: []string{constants.CodeResponseType},
			GrantTypes:    []string{constants.AuthorizationCode, constants.PKCE},
			Scopes:        []string{testScope},
			RedirectURIS:  []string{testRedirectURI},
		},
		ResponseType:        constants.CodeResponseType,
		CodeChallenge:       validCodeChallenge,
		CodeChallengeMethod: client.Plain,
	}
}
