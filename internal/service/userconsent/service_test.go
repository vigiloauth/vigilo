package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	mAuthzCodeService "github.com/vigiloauth/vigilo/internal/mocks/authzcode"
	mClientService "github.com/vigiloauth/vigilo/internal/mocks/client"
	mSessionService "github.com/vigiloauth/vigilo/internal/mocks/session"
	mUserRepo "github.com/vigiloauth/vigilo/internal/mocks/user"
	mConsentRepo "github.com/vigiloauth/vigilo/internal/mocks/userconsent"
)

const (
	testUserID      string = "user_id"
	testClientID    string = "client_id"
	testScope       string = "user:read"
	testRedirectURI string = "https://test.com/callback"
	testState       string = "test_state"
)

func TestUserConsentService_CheckUserConsent(t *testing.T) {
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}
	mockUserRepo := &mUserRepo.MockUserRepository{}
	mockSessionService := &mSessionService.MockSessionService{}
	mockClientService := &mClientService.MockClientService{}
	mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{}

	t.Run("Returns true when user has consent", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.HasConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, nil
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, mockSessionService, mockClientService, mockAuthzCodeService)
		hasConsent, err := cs.CheckUserConsent(testUserID, testClientID, testScope)

		assert.NoError(t, err)
		assert.True(t, hasConsent)
	})

	t.Run("Returns false when user does not have consent", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.HasConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return false, nil
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, mockSessionService, mockClientService, mockAuthzCodeService)
		hasConsent, err := cs.CheckUserConsent(testUserID, testClientID, testScope)

		assert.NoError(t, err)
		assert.False(t, hasConsent)
	})

	t.Run("Error is returned when a database error occurs", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return nil }
		mockConsentRepo.HasConsentFunc = func(userID, clientID, scope string) (bool, error) {
			return true, errors.NewInternalServerError()
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, mockSessionService, mockClientService, mockAuthzCodeService)
		hasConsent, err := cs.CheckUserConsent(testUserID, testClientID, testScope)

		assert.Error(t, err)
		assert.False(t, hasConsent)
	})
}

func TestUserConsentService_SaveUserConsent(t *testing.T) {
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}
	mockUserRepo := &mUserRepo.MockUserRepository{}

	t.Run("Success", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.SaveConsentFunc = func(userID, clientID, scope string) error { return nil }

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil, nil)
		err := cs.SaveUserConsent(testUserID, testClientID, testScope)

		assert.NoError(t, err)
	})

	t.Run("Error is returned when a database error occurs", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.SaveConsentFunc = func(userID, clientID, scope string) error {
			return errors.NewInternalServerError()
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil, nil)
		err := cs.SaveUserConsent(testUserID, testClientID, testScope)

		assert.Error(t, err)
	})

	t.Run("Error is returned when the user does not exist", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return nil }

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil, nil)
		err := cs.SaveUserConsent(testUserID, testClientID, testScope)

		assert.Error(t, err)
	})
}

func TestUserConsentService_RevokeUserConsent(t *testing.T) {
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}
	mockUserRepo := &mUserRepo.MockUserRepository{}

	t.Run("Consent is successfully revoked", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.RevokeConsentFunc = func(userID, clientID string) error { return nil }

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil, nil)
		err := cs.RevokeConsent(testUserID, testClientID)

		assert.NoError(t, err)
	})

	t.Run("Error is returned when there is an error revoking consent", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User {
			return &users.User{}
		}
		mockConsentRepo.RevokeConsentFunc = func(userID, clientID string) error {
			return errors.NewInternalServerError()
		}

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil, nil)
		err := cs.RevokeConsent(testUserID, testClientID)

		assert.Error(t, err)
	})

	t.Run("Error is returned when the user does not exist", func(t *testing.T) {
		mockUserRepo.GetUserByIDFunc = func(userID string) *users.User { return nil }

		cs := NewUserConsentService(mockConsentRepo, mockUserRepo, nil, nil, nil)
		err := cs.RevokeConsent(testUserID, testClientID)

		assert.Error(t, err)
	})
}

func TestUserConsentService_GetConsentDetails(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return &client.Client{ID: testClientID}
			},
		}
		mockSessionService := &mSessionService.MockSessionService{
			GetSessionDataFunc: func(r *http.Request) (*session.SessionData, error) {
				return &session.SessionData{UserID: testUserID}, nil
			},
			UpdateSessionFunc: func(r *http.Request, sessionData *session.SessionData) error {
				return nil
			},
		}

		service := NewUserConsentService(nil, nil, mockSessionService, mockClientService, nil)
		response, err := service.GetConsentDetails(testUserID, testClientID, testRedirectURI, testScope, nil)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, testClientID, response.ClientID)
	})

	t.Run("Error is returned when the request is not valid", func(t *testing.T) {
		service := NewUserConsentService(nil, nil, nil, nil, nil)
		response, err := service.GetConsentDetails("", testClientID, testRedirectURI, testScope, nil)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when retrieving session data", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return &client.Client{ID: testClientID}
			},
		}
		mockSessionService := &mSessionService.MockSessionService{
			GetSessionDataFunc: func(r *http.Request) (*session.SessionData, error) {
				return nil, errors.NewInternalServerError()
			},
		}

		service := NewUserConsentService(nil, nil, mockSessionService, mockClientService, nil)
		response, err := service.GetConsentDetails(testUserID, testClientID, testRedirectURI, testScope, nil)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when updating session", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return &client.Client{ID: testClientID}
			},
		}
		mockSessionService := &mSessionService.MockSessionService{
			GetSessionDataFunc: func(r *http.Request) (*session.SessionData, error) {
				return &session.SessionData{UserID: testUserID}, nil
			},
			UpdateSessionFunc: func(r *http.Request, sessionData *session.SessionData) error {
				return errors.NewInternalServerError()
			},
		}

		service := NewUserConsentService(nil, nil, mockSessionService, mockClientService, nil)
		response, err := service.GetConsentDetails(testUserID, testClientID, testRedirectURI, testScope, nil)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when the client does not exist", func(t *testing.T) {
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return nil
			},
		}

		service := NewUserConsentService(nil, nil, nil, mockClientService, nil)
		response, err := service.GetConsentDetails(testUserID, testClientID, testRedirectURI, testScope, nil)

		assert.Error(t, err)
		assert.Nil(t, response)
	})
}

func TestUserConsentService_ProcessUserConsent(t *testing.T) {
	mockSessionService := &mSessionService.MockSessionService{}
	mockAuthzCodeService := &mAuthzCodeService.MockAuthorizationCodeService{}
	mockConsentRepo := &mConsentRepo.MockUserConsentRepository{}

	t.Run("Error is returned for invalid request parameters", func(t *testing.T) {
		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, nil, mockAuthzCodeService)
		response, err := service.ProcessUserConsent("", testClientID, testRedirectURI, testScope, nil, nil)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when session validation fails", func(t *testing.T) {
		mockSessionService.ValidateSessionStateFunc = func(r *http.Request) (*session.SessionData, error) {
			return nil, errors.NewInternalServerError()
		}

		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, nil, mockAuthzCodeService)
		response, err := service.ProcessUserConsent(testUserID, testClientID, testRedirectURI, testScope, nil, nil)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Consent denied by user", func(t *testing.T) {
		mockSessionService.ValidateSessionStateFunc = func(r *http.Request) (*session.SessionData, error) {
			return &session.SessionData{State: testState}, nil
		}

		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, nil, mockAuthzCodeService)
		response, err := service.ProcessUserConsent(testUserID, testClientID, testRedirectURI, testScope, &consent.UserConsentRequest{Approved: false}, nil)

		assert.NoError(t, err)
		assert.NotNil(t, response)
		assert.Equal(t, "access_denied", response.Error)
	})

	t.Run("Error is returned when saving user consent fails", func(t *testing.T) {
		mockSessionService.ValidateSessionStateFunc = func(r *http.Request) (*session.SessionData, error) {
			return &session.SessionData{State: testState}, nil
		}
		mockConsentRepo.SaveConsentFunc = func(userID, clientID, scope string) error {
			return errors.NewInternalServerError()
		}

		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, nil, mockAuthzCodeService)
		response, err := service.ProcessUserConsent(testUserID, testClientID, testRedirectURI, testScope, &consent.UserConsentRequest{Approved: true}, nil)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when generating authorization code fails", func(t *testing.T) {
		mockSessionService.ValidateSessionStateFunc = func(r *http.Request) (*session.SessionData, error) {
			return &session.SessionData{State: testState}, nil
		}
		mockConsentRepo.SaveConsentFunc = func(userID, clientID, scope string) error {
			return nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(req *client.ClientAuthorizationRequest) (string, error) {
			return "", errors.NewInternalServerError()
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return &client.Client{ID: testClientID}
			},
		}

		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, mockClientService, mockAuthzCodeService)
		response, err := service.ProcessUserConsent(testUserID, testClientID, testRedirectURI, testScope, &consent.UserConsentRequest{Approved: true}, nil)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Error is returned when clearing session state fails", func(t *testing.T) {
		mockSessionService.ValidateSessionStateFunc = func(r *http.Request) (*session.SessionData, error) {
			return &session.SessionData{State: testState}, nil
		}
		mockConsentRepo.SaveConsentFunc = func(userID, clientID, scope string) error {
			return nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(req *client.ClientAuthorizationRequest) (string, error) {
			return "auth_code", nil
		}
		mockSessionService.ClearStateFromSessionFunc = func(sessionData *session.SessionData) error {
			return errors.NewInternalServerError()
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return &client.Client{ID: testClientID}
			},
		}

		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, mockClientService, mockAuthzCodeService)
		response, err := service.ProcessUserConsent(testUserID, testClientID, testRedirectURI, testScope, &consent.UserConsentRequest{Approved: true}, nil)

		assert.Error(t, err)
		assert.Nil(t, response)
	})

	t.Run("Success when consent is approved", func(t *testing.T) {
		mockSessionService.ValidateSessionStateFunc = func(r *http.Request) (*session.SessionData, error) {
			return &session.SessionData{State: testState}, nil
		}
		mockConsentRepo.SaveConsentFunc = func(userID, clientID, scope string) error {
			return nil
		}
		mockAuthzCodeService.GenerateAuthorizationCodeFunc = func(req *client.ClientAuthorizationRequest) (string, error) {
			return "auth_code", nil
		}
		mockSessionService.ClearStateFromSessionFunc = func(sessionData *session.SessionData) error {
			return nil
		}
		mockClientService := &mClientService.MockClientService{
			GetClientByIDFunc: func(clientID string) *client.Client {
				return &client.Client{ID: testClientID}
			},
		}

		service := NewUserConsentService(mockConsentRepo, nil, mockSessionService, mockClientService, mockAuthzCodeService)
		response, err := service.ProcessUserConsent(testUserID, testClientID, testRedirectURI, testScope, &consent.UserConsentRequest{Approved: true}, nil)

		assert.NoError(t, err)
		assert.NotNil(t, response)
	})
}
