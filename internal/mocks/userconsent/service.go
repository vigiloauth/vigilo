package mocks

type MockConsentService struct {
	CheckUserConsentFunc func(userID, clientID, scope string) (bool, error)
	SaveUserConsentFunc  func(userID, clientID, scope string) error
	RevokeConsentFunc    func(userID, clientID string) error
}

func (m *MockConsentService) CheckUserConsent(userID, clientID, scope string) (bool, error) {
	return m.CheckUserConsentFunc(userID, clientID, scope)
}

func (m *MockConsentService) SaveUserConsent(userID, clientID, scope string) error {
	return m.SaveUserConsentFunc(userID, clientID, scope)
}

func (m *MockConsentService) RevokeConsent(userID, clientID string) error {
	return m.RevokeConsentFunc(userID, clientID)
}
