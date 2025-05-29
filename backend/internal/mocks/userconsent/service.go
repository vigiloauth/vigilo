package mocks

import (
	"context"
	"net/http"

	user "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ user.UserConsentService = (*MockUserConsentService)(nil)

type MockUserConsentService struct {
	CheckUserConsentFunc   func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error)
	SaveUserConsentFunc    func(ctx context.Context, userID, clientID string, scope types.Scope) error
	RevokeConsentFunc      func(ctx context.Context, userID, clientID string) error
	GetConsentDetailsFunc  func(userID, clientID, redirectURI, state string, scope types.Scope, responseType, nonce, display string, r *http.Request) (*user.UserConsentResponse, error)
	ProcessUserConsentFunc func(userID, clientID, redirectURI string, scope types.Scope, consentRequest *user.UserConsentRequest, r *http.Request) (*user.UserConsentResponse, error)
}

func (m *MockUserConsentService) GetConsentDetails(userID, clientID, redirectURI, state string, scope types.Scope, responseType, nonce, display string, r *http.Request) (*user.UserConsentResponse, error) {
	return m.GetConsentDetailsFunc(userID, clientID, redirectURI, state, scope, responseType, nonce, display, r)
}

func (m *MockUserConsentService) ProcessUserConsent(userID, clientID, redirectURI string, scope types.Scope, consentRequest *user.UserConsentRequest, r *http.Request) (*user.UserConsentResponse, error) {
	return m.ProcessUserConsentFunc(userID, clientID, redirectURI, scope, consentRequest, r)
}

func (m *MockUserConsentService) CheckUserConsent(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
	return m.CheckUserConsentFunc(ctx, userID, clientID, scope)
}

func (m *MockUserConsentService) SaveUserConsent(ctx context.Context, userID, clientID string, scope types.Scope) error {
	return m.SaveUserConsentFunc(ctx, userID, clientID, scope)
}

func (m *MockUserConsentService) RevokeConsent(ctx context.Context, userID, clientID string) error {
	return m.RevokeConsentFunc(ctx, userID, clientID)
}
