package mocks

type MockUserConsentService struct {
	CheckUserConsentFunc func(userID, clientID, scope string) (bool, error)
	SaveUserConsentFunc  func(userID, clientID, scope string) error
	RevokeConsentFunc    func(userID, clientID string) error
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
