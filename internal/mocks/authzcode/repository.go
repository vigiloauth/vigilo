package mocks

import (
	"time"

	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
)

// MockAuthorizationCodeRepository is a mock implementation of the authz.AuthorizationCodeStore interface
type MockAuthorizationCodeRepository struct {
	// StoreAuthorizationCodeFunc is a mock function for the StoreAuthorizationCode method.
	StoreAuthorizationCodeFunc func(code string, data *authz.AuthorizationCodeData, expiresAt time.Time) error

	// GetAuthorizationCodeFunc is a mock function for the GetAuthorizationCode method.
	GetAuthorizationCodeFunc func(code string) (*authz.AuthorizationCodeData, error)

	// DeleteAuthorizationCodeFunc is a mock function for the DeleteAuthorizationCode method.
	DeleteAuthorizationCodeFunc func(code string) error

	// CleanupExpiredAuthorizationCodesFunc is a mock function for the CleanupExpiredAuthorizationCodes method.
	CleanupExpiredAuthorizationCodesFunc func() error

	UpdateAuthorizationCodeFunc func(code string, authData *authz.AuthorizationCodeData) error

	// CloseFunc is a mock function for the Close method.
	CloseFunc func()
}

// StoreAuthorizationCode calls the mock StoreAuthorizationCodeFunc.
func (m *MockAuthorizationCodeRepository) StoreAuthorizationCode(
	code string,
	data *authz.AuthorizationCodeData,
	expiresAt time.Time,
) error {
	return m.StoreAuthorizationCodeFunc(code, data, expiresAt)
}

// GetAuthorizationCode calls the mock GetAuthorizationCodeFunc.
func (m *MockAuthorizationCodeRepository) GetAuthorizationCode(code string) (*authz.AuthorizationCodeData, error) {
	return m.GetAuthorizationCodeFunc(code)
}

// DeleteAuthorizationCode calls the mock DeleteAuthorizationCodeFunc.
func (m *MockAuthorizationCodeRepository) DeleteAuthorizationCode(code string) error {
	return m.DeleteAuthorizationCodeFunc(code)
}

// CleanupExpiredAuthorizationCodes calls the mock CleanupExpiredAuthorizationCodesFunc.
func (m *MockAuthorizationCodeRepository) CleanupExpiredAuthorizationCodes() error {
	return m.CleanupExpiredAuthorizationCodesFunc()
}

func (m *MockAuthorizationCodeRepository) UpdateAuthorizationCode(code string, authData *authz.AuthorizationCodeData) error {
	return m.UpdateAuthorizationCodeFunc(code, authData)
}

// Close calls the mock CloseFunc.
func (m *MockAuthorizationCodeRepository) Close() {
	m.CloseFunc()
}
