package mocks

import (
	"context"
	"net/http"

	user "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
)

var _ user.UserConsentService = (*MockUserConsentService)(nil)

type MockUserConsentService struct {
	CheckUserConsentFunc   func(ctx context.Context, userID, clientID, scope string) (bool, error)
	SaveUserConsentFunc    func(ctx context.Context, userID, clientID, scope string) error
	RevokeConsentFunc      func(ctx context.Context, userID, clientID string) error
	GetConsentDetailsFunc  func(userID, clientID, redirectURI, scope string, r *http.Request) (*user.UserConsentResponse, error)
	ProcessUserConsentFunc func(userID, clientID, redirectURI, scope string, consentRequest *user.UserConsentRequest, r *http.Request) (*user.UserConsentResponse, error)
}

func (m *MockUserConsentService) GetConsentDetails(userID, clientID, redirectURI, scope string, r *http.Request) (*user.UserConsentResponse, error) {
	return m.GetConsentDetailsFunc(userID, clientID, redirectURI, scope, r)
}

func (m *MockUserConsentService) ProcessUserConsent(userID, clientID, redirectURI, scope string, consentRequest *user.UserConsentRequest, r *http.Request) (*user.UserConsentResponse, error) {
	return m.ProcessUserConsentFunc(userID, clientID, redirectURI, scope, consentRequest, r)
}

func (m *MockUserConsentService) CheckUserConsent(ctx context.Context, userID, clientID, scope string) (bool, error) {
	return m.CheckUserConsentFunc(ctx, userID, clientID, scope)
}

func (m *MockUserConsentService) SaveUserConsent(ctx context.Context, userID, clientID, scope string) error {
	return m.SaveUserConsentFunc(ctx, userID, clientID, scope)
}

func (m *MockUserConsentService) RevokeConsent(ctx context.Context, userID, clientID string) error {
	return m.RevokeConsentFunc(ctx, userID, clientID)
}
