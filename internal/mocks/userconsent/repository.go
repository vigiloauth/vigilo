package mocks

// MockConsentRepository is a mock implementation of the consent.ConsentStore interface.
type MockConsentRepository struct {
	// HasConsentFunc is a mock function for the HasConsent method.
	HasConsentFunc func(userID, clientID, scope string) (bool, error)

	// SaveConsentFunc is a mock function for the SaveConsent method.
	SaveConsentFunc func(userID, clientID, scope string) error

	// RevokeConsentFunc is a mock function for the RevokeConsent method.
	RevokeConsentFunc func(userID, clientID string) error
}

// HasConsent calls the mock HasConsentFunc.
func (m *MockConsentRepository) HasConsent(userID, clientID, scope string) (bool, error) {
	return m.HasConsentFunc(userID, clientID, scope)
}

// SaveConsent calls the mock SaveConsentFunc.
func (m *MockConsentRepository) SaveConsent(userID, clientID, scope string) error {
	return m.SaveConsentFunc(userID, clientID, scope)
}

// RevokeConsent calls the mock RevokeConsentFunc.
func (m *MockConsentRepository) RevokeConsent(userID, clientID string) error {
	return m.RevokeConsentFunc(userID, clientID)
}
