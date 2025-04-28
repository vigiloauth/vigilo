package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"github.com/google/uuid"
	"github.com/vigiloauth/vigilo/internal/errors"
	"golang.org/x/crypto/bcrypt"
)

// HashString takes a plain text string and returns a hashed
// version of it using bcrypt with the default cost.
//
// Parameters:
//   - plainStr string: The string to be encrypted.
//
// Returns:
//   - string: The encrypted string.
//   - error: Error if an error occurs hashing the string.
func HashString(plainStr string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainStr), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// GenerateJWKKeyID generates a JWK Key ID (kid) by hashing the provided key
// using SHA-256 and encoding it in base64 URL format.
//
// Parameters:
//   - key string: The key to generate the JWK Key ID from.
//
// Returns:
//   - string: The base64 URL encoded JWK Key ID.
func GenerateJWKKeyID(key string) string {
	hasher := sha256.New()
	hasher.Write([]byte(key))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

// CompareHash compares a plain text string with a hashed
// string and returns true if they match.
//
// Parameters:
//   - plainStr string: The plain text string.
//   - hashStr string: The encrypted string.
//
// Returns:
//   - bool: True if they match, otherwise false.
func CompareHash(plainStr, hashStr string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashStr), []byte(plainStr))
	return err == nil
}

// GenerateUUID generates a new universally unique identifier (UUID) as a string.
// It uses the uuid package to create a version 4 UUID, which is a randomly generated UUID.
//
// Returns:
//   - string: A string representation of the generated UUID.
func GenerateUUID() string {
	uuid := uuid.New().String()
	return uuid
}

// EncodeSHA256 hashes the input using SHA-256 and encodes it in base64 URL format.
func EncodeSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GenerateRandomString generates a cryptographically secure random string of the specified length.
//
// Parameters:
//   - length int: The desired length of the random string.
//
// Returns:
//   - string: The random generated string.
//   - error: An error if creating the random string fails.
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// EncryptString encrypts a plaintext string using AES-GCM and a secret key.
// It returns the base64-encoded encrypted string.
//
// Parameters:
//   - plaintext string: The plaintext string to encrypt.
//   - secretKey string: A 32-byte key for AES-256 encryption (make sure to store this securely).
//
// Returns:
//   - string: The encrypted text, base64-encoded.
//   - error: Error if an encryption issue occurs.
func EncryptString(plaintext, secretKey string) (string, error) {
	key, err := decodeAndValidateSecretKey(secretKey)
	if err != nil {
		return "", errors.NewInternalServerError()
	}

	block, err := generateAESCipherBlock(key)
	if err != nil {
		return "", errors.NewInternalServerError()
	}

	nonce, err := generateRandomNonce()
	if err != nil {
		return "", errors.NewInternalServerError()
	}

	aesGCM, err := generateGCMCipher(block)
	if err != nil {
		return "", errors.NewInternalServerError()
	}

	cipherText := aesGCM.Seal(nil, nonce, []byte(plaintext), nil)
	result := append(nonce, cipherText...)
	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptString decrypts a base64-encoded cipher text string using AES-GCM and a secret key.
// It returns the decrypted plaintext string.
//
// Parameters:
//   - cipherTextBase64 string: The base64-encoded encrypted string.
//   - secretKey: string The secret key used for encryption.
//
// Returns:
//   - string: The decrypted plaintext string.
//   - error: Error if decryption fails.
func DecryptString(cipherTextBase64, secretKey string) (string, error) {
	key, err := decodeAndValidateSecretKey(secretKey)
	if err != nil {
		return "", errors.NewInternalServerError()
	}

	cipherText, err := decodeBase64String(cipherTextBase64)
	if err != nil {
		return "", errors.NewInternalServerError()
	}

	nonce := cipherText[:12]
	block, err := generateAESCipherBlock(key)
	if err != nil {
		return "", errors.NewInternalServerError()
	}

	aesGCM, err := generateGCMCipher(block)
	if err != nil {
		return "", err
	}

	plaintext, err := decryptCipherText(aesGCM, nonce, cipherText[12:])
	if err != nil {
		return "", errors.NewInternalServerError()
	}

	return string(plaintext), nil
}

// EncryptBytes encrypts a given byte slice using AES-GCM mode.
//
// Parameters:
//   - plainBytes []byte: The byte slice to encrypt.
//   - secretKey []byte: The key used for encryption. It must be 32 bytes long for AES-256.
//
// Returns:
//   - string: The base64-encoded encrypted data.
//   - error: Any error that occurs during encryption.
func EncryptBytes(plainBytes []byte, secretKey string) (string, error) {
	key, err := decodeAndValidateSecretKey(secretKey)
	if err != nil {
		return "", err
	}

	block, err := generateAESCipherBlock(key)
	if err != nil {
		return "", err
	}

	nonce, err := generateRandomNonce()
	if err != nil {
		return "", err
	}

	aesGCM, err := generateGCMCipher(block)
	if err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nil, nonce, plainBytes, nil)
	result := append(nonce, cipherText...)
	encodedResult := base64.StdEncoding.EncodeToString(result)

	return encodedResult, nil
}

// DecryptBytes decrypts an AES-GCM encrypted string (base64 encoded) into a byte slice.
//
// Parameters:
//   - encryptedData string: The base64 encoded encrypted data (nonce + cipherText).
//   - secretKey string: The key used for decryption. It must be 32 bytes long for AES-256.
//
// Returns:
//   - []byte: The decrypted byte slice (plain data).
//   - error: Any error that occurs during decryption.
func DecryptBytes(encryptedData string, secretKey string) ([]byte, error) {
	key, err := decodeAndValidateSecretKey(secretKey)
	if err != nil {
		return nil, err
	}

	// Decode the base64 encoded data
	decodedData, err := decodeBase64String(encryptedData)
	if err != nil {
		return nil, err
	}

	if len(decodedData) < 12 {
		err := errors.New(errors.ErrCodeInvalidInput, "invalid data length")
		return nil, err
	}

	nonce := decodedData[:12]
	cipherText := decodedData[12:]

	block, err := generateAESCipherBlock(key)
	if err != nil {
		return nil, errors.NewInternalServerError()
	}

	aesGCM, err := generateGCMCipher(block)
	if err != nil {
		return nil, errors.NewInternalServerError()
	}

	plainBytes, err := decryptCipherText(aesGCM, nonce, cipherText)
	if err != nil {
		return nil, errors.NewInternalServerError()
	}

	return plainBytes, nil
}

func decryptCipherText(aesGCM cipher.AEAD, nonce, cipherText []byte) ([]byte, error) {
	plainBytes, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	return plainBytes, nil
}

func decodeAndValidateSecretKey(secretKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		return nil, err
	} else if len(key) != 32 {
		err := errors.New(errors.ErrCodeInvalidInput, "secret key must be 32 bytes for AES-256")
		return nil, err
	}

	return key, nil
}

func generateAESCipherBlock(key []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return block, nil
}

func generateGCMCipher(block cipher.Block) (cipher.AEAD, error) {
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesGCM, nil
}

func generateRandomNonce() ([]byte, error) {
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}

func decodeBase64String(cipherTextBase64 string) ([]byte, error) {
	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return nil, err
	}

	return cipherText, nil
}
