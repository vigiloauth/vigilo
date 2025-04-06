package mocks

import (
	"net/http"

	user "github.com/vigiloauth/vigilo/internal/domain/userconsent"
)

type MockUserConsentService struct {
	CheckUserConsentFunc   func(userID, clientID, scope string) (bool, error)
	SaveUserConsentFunc    func(userID, clientID, scope string) error
	RevokeConsentFunc      func(userID, clientID string) error
	GetConsentDetailsFunc  func(userID, clientID, redirectURI, scope string, r *http.Request) (*user.UserConsentResponse, error)
	ProcessUserConsentFunc func(userID, clientID, redirectURI, scope string, consentRequest *user.UserConsentRequest, r *http.Request) (*user.UserConsentResponse, error)
}

func (m *MockUserConsentService) GetConsentDetails(userID, clientID, redirectURI, scope string, r *http.Request) (*user.UserConsentResponse, error) {
	return m.GetConsentDetailsFunc(userID, clientID, redirectURI, scope, r)
}

func (m *MockUserConsentService) ProcessUserConsent(userID, clientID, redirectURI, scope string, consentRequest *user.UserConsentRequest, r *http.Request) (*user.UserConsentResponse, error) {
	return m.ProcessUserConsentFunc(userID, clientID, redirectURI, scope, consentRequest, r)
}

func (m *MockUserConsentService) CheckUserConsent(userID, clientID, scope string) (bool, error) {
	return m.CheckUserConsentFunc(userID, clientID, scope)
}

func (m *MockUserConsentService) SaveUserConsent(userID, clientID, scope string) error {
	return m.SaveUserConsentFunc(userID, clientID, scope)
}

func (m *MockUserConsentService) RevokeConsent(userID, clientID string) error {
	return m.RevokeConsentFunc(userID, clientID)
}
