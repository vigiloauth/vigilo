package mocks

import domain "github.com/vigiloauth/vigilo/internal/domain/encryption"

var _ domain.EncryptionService = (*MockEncryptionService)(nil)

type MockEncryptionService struct {
	EncryptStringFunc func(plainStr, secretKey string) (string, error)
	DecryptStringFunc func(encryptedStr, secretKey string) (string, error)
	EncryptBytesFunc  func(plainBytes []byte, secretKey string) (string, error)
	DecryptBytesFunc  func(encryptedBytes, secretKey string) ([]byte, error)
}

func (m *MockEncryptionService) EncryptString(plainStr string, secretKey string) (string, error) {
	return m.EncryptStringFunc(plainStr, secretKey)
}
func (m *MockEncryptionService) DecryptString(encryptedStr string, secretKey string) (string, error) {
	return m.DecryptStringFunc(encryptedStr, secretKey)
}
func (m *MockEncryptionService) EncryptBytes(plainBytes []byte, secretKey string) (string, error) {
	return m.EncryptBytesFunc(plainBytes, secretKey)
}

func (m *MockEncryptionService) DecryptBytes(encryptedBytes, secretKey string) ([]byte, error) {
	return m.DecryptBytesFunc(encryptedBytes, secretKey)
}
