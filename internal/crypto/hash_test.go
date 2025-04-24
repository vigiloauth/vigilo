package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHash_EncryptString(t *testing.T) {
	secretKey := getSecretKey()
	plainStr := "string-to-encrypted"

	encryptedStr, err := EncryptString(plainStr, secretKey)
	assert.NoError(t, err)
	assert.NotEqual(t, plainStr, encryptedStr)
}

func TestHash_DecryptString(t *testing.T) {
	secretKey := getSecretKey()
	plainStr := "string-to-encrypted"

	encryptedStr, err := EncryptString(plainStr, secretKey)
	assert.NoError(t, err)

	decryptedStr, err := DecryptString(encryptedStr, secretKey)
	assert.NoError(t, err)
	assert.Equal(t, plainStr, decryptedStr)
}

func TestHash_EncryptBytes(t *testing.T) {
	secretKey := getSecretKey()
	plainBytes := []byte("string-to-encrypted")

	encryptedBytes, err := EncryptBytes(plainBytes, secretKey)
	assert.NoError(t, err)
	assert.NotEqual(t, plainBytes, encryptedBytes)
}

func TestHash_DecryptBytes(t *testing.T) {
	secretKey := getSecretKey()
	plainBytes := []byte("string-to-encrypted")

	encryptedBytes, err := EncryptBytes(plainBytes, secretKey)
	assert.NoError(t, err)

	decryptedBytes, err := DecryptBytes(encryptedBytes, secretKey)
	assert.NoError(t, err)
	assert.Equal(t, plainBytes, decryptedBytes)
}

func getSecretKey() string {
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key)
}
