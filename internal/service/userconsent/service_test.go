package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mClientService "github.com/vigiloauth/vigilo/v2/internal/mocks/client"
	mSessionService "github.com/vigiloauth/vigilo/v2/internal/mocks/session"
	mUserRepo "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
	mConsentRepo "github.com/vigiloauth/vigilo/v2/internal/mocks/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

const (
	testUserID       string = "user_id"
	testClientID     string = "client_id"
	testRedirectURI  string = "https://test.com/callback"
	testState        string = "test_state"
	testResponseType string = "code"
	testNonce        string = "nonce"
	testDisplay      string = "page"
)

func TestUserConsentService_CheckUserConsent(t *testing.T) {
	ctx := context.Background()
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockSessionService := &mSessionService.MockSessionService{}
	mockClientService := &mClientService.MockClientManager{}

	t.Run("Returns true when user has consent", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(ctx context.Context, userID string) (*users.User, error) {
			return &users.User{}, nil
		}
		mockConsentRepo.HasConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
			return true, nil
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, mockSessionService, mockClientService)
		hasConsent, err := cs.CheckUserConsent(ctx, testUserID, testClientID, types.OpenIDScope)

		require.NoError(t, err)
		assert.True(t, hasConsent)
	})

	t.Run("Returns false when user does not have consent", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(ctx context.Context, userID string) (*users.User, error) {
			return &users.User{}, nil
		}
		mockConsentRepo.HasConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
			return false, nil
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, mockSessionService, mockClientService)
		hasConsent, err := cs.CheckUserConsent(ctx, testUserID, testClientID, types.OpenIDScope)

		require.NoError(t, err)
		assert.False(t, hasConsent)
	})

	t.Run("Error is returned when a database error occurs", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(ctx context.Context, userID string) (*users.User, error) { return nil, nil }
		mockConsentRepo.HasConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
			return false, errors.NewInternalServerError("")
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, mockSessionService, mockClientService)
		hasConsent, err := cs.CheckUserConsent(ctx, testUserID, testClientID, types.OpenIDScope)

		require.Error(t, err)
		assert.False(t, hasConsent)
	})
}

func TestUserConsentService_SaveUserConsent(t *testing.T) {
	ctx := context.Background()
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}
	mockUserRepo := &mUserRepo.MockUserRepository{}

	t.Run("Success", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(ctx context.Context, userID string) (*users.User, error) {
			return &users.User{}, nil
		}
		mockConsentRepo.SaveConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) error { return nil }

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil)
		err := cs.SaveUserConsent(ctx, testUserID, testClientID, types.OpenIDScope)

		require.NoError(t, err)
	})

	t.Run("Error is returned when a database error occurs", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(ctx context.Context, userID string) (*users.User, error) {
			return &users.User{}, nil
		}
		mockConsentRepo.SaveConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) error {
			return errors.NewInternalServerError("")
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil)
		err := cs.SaveUserConsent(ctx, testUserID, testClientID, types.OpenIDScope)

		require.Error(t, err)
	})

	t.Run("Error is returned when the user does not exist", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(ctx context.Context, userID string) (*users.User, error) { return nil, nil }

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil)
		err := cs.SaveUserConsent(ctx, testUserID, testClientID, types.OpenIDScope)

		require.Error(t, err)
	})
}

func TestUserConsentService_RevokeUserConsent(t *testing.T) {
	ctx := context.Background()
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}
	mockUserRepo := &mUserRepo.MockUserRepository{}

	t.Run("Consent is successfully revoked", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(ctx context.Context, userID string) (*users.User, error) {
			return &users.User{}, nil
		}
		mockConsentRepo.RevokeConsentFunc = func(ctx context.Context, userID, clientID string) error { return nil }

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil)
		err := cs.RevokeConsent(ctx, testUserID, testClientID)

		require.NoError(t, err)
	})

	t.Run("Error is returned when there is an error revoking consent", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(ctx context.Context, userID string) (*users.User, error) {
			return &users.User{}, nil
		}
		mockConsentRepo.RevokeConsentFunc = func(ctx context.Context, userID, clientID string) error {
			return errors.NewInternalServerError("")
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil)
		err := cs.RevokeConsent(ctx, testUserID, testClientID)

		require.Error(t, err)
	})

	t.Run("Error is returned when the user does not exist", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(ctx context.Context, userID string) (*users.User, error) {
			return &users.User{}, nil
		}
		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil)
		err := cs.RevokeConsent(ctx, testUserID, testClientID)

		require.Error(t, err)
	})
}

func TestUserConsentService_GetConsentDetails(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockClientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{ID: testClientID}, nil
			},
		}
		mockSessionService := &mSessionService.MockSessionService{
			GetSessionDataFunc: func(r *http.Request) (*session.SessionData, error) {
				return &session.SessionData{UserID: testUserID, ID: "sess-1234"}, nil
			},
			UpdateSessionFunc: func(r *http.Request, sessionData *session.SessionData) error {
				return nil
			},
		}
		userRepo := &mUserRepo.MockUserRepository{
			GetUserByIDFunc: func(ctx context.Context, userID string) (*users.User, error) {
				return &users.User{ID: userID}, nil
			},
		}
		consentRepo := &mConsentRepo.MockUserConsentRepository{
			HasConsentFunc: func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
				return true, nil
			},
			SaveConsentFunc: func(ctx context.Context, userID, clientID string, scope types.Scope) error { return nil },
		}

		service := NewUserConsentService(consentRepo, userRepo, mockSessionService, mockClientService)
		req := &http.Request{}
		response, err := service.GetConsentDetails(testUserID, testClientID, testRedirectURI, testState, types.OpenIDScope, testResponseType, testNonce, testDisplay, req)

		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("Error is returned when the request is not valid", func(t *testing.T) {
		service := NewUserConsentService(nil, nil, nil, nil)
		req := &http.Request{}
		response, err := service.GetConsentDetails("", testClientID, testRedirectURI, testState, types.OpenIDScope, testResponseType, testNonce, testDisplay, req)

		require.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when retrieving session data", func(t *testing.T) {
		mockClientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{ID: testClientID}, nil
			},
		}
		mockSessionService := &mSessionService.MockSessionService{
			GetSessionDataFunc: func(r *http.Request) (*session.SessionData, error) {
				return nil, errors.NewInternalServerError("")
			},
		}

		service := NewUserConsentService(nil, nil, mockSessionService, mockClientService)
		req := &http.Request{}
		response, err := service.GetConsentDetails(testUserID, testClientID, testRedirectURI, testState, types.OpenIDScope, testResponseType, testNonce, testDisplay, req)

		require.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when updating session", func(t *testing.T) {
		mockClientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{ID: testClientID}, nil
			},
		}
		mockSessionService := &mSessionService.MockSessionService{
			GetSessionDataFunc: func(r *http.Request) (*session.SessionData, error) {
				return &session.SessionData{UserID: testUserID}, nil
			},
			UpdateSessionFunc: func(r *http.Request, sessionData *session.SessionData) error {
				return errors.NewInternalServerError("")
			},
		}

		service := NewUserConsentService(nil, nil, mockSessionService, mockClientService)
		req := &http.Request{}
		response, err := service.GetConsentDetails(testUserID, testClientID, testRedirectURI, testState, types.OpenIDScope, testResponseType, testNonce, testDisplay, req)

		require.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when the client does not exist", func(t *testing.T) {
		mockClientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return nil, errors.New(errors.ErrCodeClientNotFound, "client not found")
			},
		}
		service := NewUserConsentService(nil, nil, nil, mockClientService)
		req := &http.Request{}
		response, err := service.GetConsentDetails(testUserID, testClientID, testRedirectURI, testState, types.OpenIDScope, testResponseType, testNonce, testDisplay, req)

		require.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestUserConsentService_ProcessUserConsent(t *testing.T) {
	mockSessionService := &mSessionService.MockSessionService{}
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}

	t.Run("Error is returned for invalid request parameters", func(t *testing.T) {
		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, nil)
		req := &http.Request{}
		response, err := service.ProcessUserConsent("", testClientID, testRedirectURI, types.OpenIDScope, nil, req)

		require.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Consent denied by user", func(t *testing.T) {
		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, nil)
		req := &http.Request{}
		response, err := service.ProcessUserConsent(testUserID, testClientID, testRedirectURI, types.OpenIDScope, &consent.UserConsentRequest{Approved: false}, req)

		require.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, "access_denied", response.Error)
	})

	t.Run("Error is returned when saving user consent fails", func(t *testing.T) {
		mockConsentRepo.SaveConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) error {
			return errors.NewInternalServerError("")
		}

		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, nil)
		req := &http.Request{}
		response, err := service.ProcessUserConsent(testUserID, testClientID, testRedirectURI, types.OpenIDScope, &consent.UserConsentRequest{Approved: true}, req)

		require.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Success when consent is approved", func(t *testing.T) {
		mockConsentRepo.SaveConsentFunc = func(ctx context.Context, userID, clientID string, scope types.Scope) error {
			return nil
		}
		mockClientService := &mClientService.MockClientManager{
			GetClientByIDFunc: func(ctx context.Context, clientID string) (*client.Client, error) {
				return &client.Client{ID: testClientID}, nil
			},
		}

		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, mockClientService)
		response, err := service.ProcessUserConsent(testUserID, testClientID, testRedirectURI, types.OpenIDScope, &consent.UserConsentRequest{Approved: true}, &http.Request{})

		require.NoError(t, err)
		assert.NotNil(t, response)
	})
}
