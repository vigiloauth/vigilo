package mocks

import domain "github.com/vigiloauth/vigilo/v2/internal/domain/crypto"

var _ domain.Cryptographer = (*MockCryptographer)(nil)

type MockCryptographer struct {
	EncryptStringFunc        func(plainStr, secretKey string) (string, error)
	DecryptStringFunc        func(encryptedStr, secretKey string) (string, error)
	EncryptBytesFunc         func(plainBytes []byte, secretKey string) (string, error)
	DecryptBytesFunc         func(encryptedBytes, secretKey string) ([]byte, error)
	HashStringFunc           func(plainStr string) (string, error)
	GenerateRandomStringFunc func(length int) (string, error)
}

func (m *MockCryptographer) EncryptString(plainStr string, secretKey string) (string, error) {
	return m.EncryptStringFunc(plainStr, secretKey)
}
func (m *MockCryptographer) DecryptString(encryptedStr string, secretKey string) (string, error) {
	return m.DecryptStringFunc(encryptedStr, secretKey)
}
func (m *MockCryptographer) EncryptBytes(plainBytes []byte, secretKey string) (string, error) {
	return m.EncryptBytesFunc(plainBytes, secretKey)
}

func (m *MockCryptographer) DecryptBytes(encryptedBytes, secretKey string) ([]byte, error) {
	return m.DecryptBytesFunc(encryptedBytes, secretKey)
}

func (m *MockCryptographer) HashString(plainStr string) (string, error) {
	return m.HashStringFunc(plainStr)
}
func (m *MockCryptographer) GenerateRandomString(length int) (string, error) {
	return m.GenerateRandomStringFunc(length)
}
