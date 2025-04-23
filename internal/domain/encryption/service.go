package domain

type EncryptionService interface {
	EncryptString(plainStr, secretKey string) (string, error)
	DecryptString(encryptedStr, secretKey string) (string, error)
	EncryptBytes(plainBytes []byte, secretKey string) (string, error)
	DecryptBytes(encryptedBytes, secretKey string) ([]byte, error)
}
