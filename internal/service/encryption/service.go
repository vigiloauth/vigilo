package service

import (
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/encryption"
)

var _ domain.EncryptionService = (*encryptionService)(nil)

type encryptionService struct{}

func NewEncryptionService() domain.EncryptionService {
	return &encryptionService{}
}

func (e *encryptionService) EncryptString(plainStr, secretKey string) (string, error) {
	return crypto.EncryptString(plainStr, secretKey)
}

func (e *encryptionService) DecryptString(encryptedStr, secretKey string) (string, error) {
	return crypto.DecryptString(encryptedStr, secretKey)
}

func (e *encryptionService) EncryptBytes(plainBytes []byte, secretKey string) (string, error) {
	return crypto.EncryptBytes(plainBytes, secretKey)
}

func (e *encryptionService) DecryptBytes(encryptedBytes, secretKey string) ([]byte, error) {
	return crypto.DecryptBytes(encryptedBytes, secretKey)
}
