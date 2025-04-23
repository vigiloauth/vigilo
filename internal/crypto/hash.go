package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"github.com/google/uuid"
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

var logger = config.GetServerConfig().Logger()

const module = "Crypto"

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
		logger.Error(module, "", "[HashString]: Error hashing string: %v", err)
		return "", err
	}
	return string(hash), nil
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
	logger.Warn(module, "", "[CompareHash]: Error comparing hashes")
	return err == nil
}

// GenerateUUID generates a new universally unique identifier (UUID) as a string.
// It uses the uuid package to create a version 4 UUID, which is a randomly generated UUID.
//
// Returns:
//   - string: A string representation of the generated UUID.
func GenerateUUID() string {
	uuid := uuid.New().String()
	logger.Debug(module, "", "[GenerateUUID]: Generated UUID: [%s]", utils.TruncateSensitive(uuid))
	return uuid
}

// EncodeSHA256 hashes the input using SHA-256 and encodes it in base64 URL format.
func EncodeSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// GenerateRandomString generates a cryptographically secure random string of the specified length.
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
//   - plaintext: The plaintext string to encrypt.
//   - secretKey: A 32-byte key for AES-256 encryption (make sure to store this securely).
//
// Returns:
//   - string: The encrypted text, base64-encoded.
//   - error: Error if an encryption issue occurs.
func EncryptString(plaintext, secretKey string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		logger.Error(module, "", "[EncryptString]: Error decoding base64 secret key: %v", err)
		return "", errors.NewInternalServerError()
	} else if len(key) != 32 {
		err := errors.New(errors.ErrCodeInvalidInput, "secret key must be 32 bytes for AES-256")
		logger.Error(module, "", "[EncryptString]: Invalid input: %v", err)
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error(module, "", "[EncryptString]: Error creating AES cipher: %v", err)
		return "", errors.NewInternalServerError()
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		logger.Error(module, "", "[EncryptString]: Error generating nonce: %v", err)
		return "", errors.NewInternalServerError()
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error(module, "", "[EncryptString]: Error creating GCM cipher: %v", err)
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
//   - cipherTextBase64: The base64-encoded encrypted string.
//   - secretKey: The secret key used for encryption.
//
// Returns:
//   - string: The decrypted plaintext string.
//   - error: Error if decryption fails.
func DecryptString(cipherTextBase64, secretKey string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		logger.Error(module, "", "[DecryptString]: Error decoding base64 secret key: %v", err)
		return "", errors.NewInternalServerError()
	} else if len(key) != 32 {
		err := errors.New(errors.ErrCodeInvalidInput, "secret key must be 32 bytes for AES-256")
		logger.Error(module, "", "[DecryptString]: Invalid input: %v", err)
		return "", err
	}

	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		logger.Error(module, "", "[DecryptString]: Error decoding base64 cipher text: %v", err)
		return "", errors.NewInternalServerError()
	}

	nonce := cipherText[:12]
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error(module, "", "[DecryptString]: Error creating AES cipher: %v", err)
		return "", errors.NewInternalServerError()
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error(module, "", "[DecryptString]: Error creating GCM cipher: %v", err)
		return "", errors.NewInternalServerError()
	}

	plaintext, err := aesGCM.Open(nil, nonce, cipherText[12:], nil)
	if err != nil {
		logger.Error(module, "", "[DecryptString]: Error decrypting cipher text: %v", err)
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
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		logger.Error(module, "", "[EncryptBytes]: Error decoding base64 secret key: %v", err)
		return "", errors.NewInternalServerError()
	} else if len(key) != 32 {
		err := errors.New(errors.ErrCodeInvalidInput, "secret key must be 32 bytes for AES-256")
		logger.Error(module, "", "[EncryptBytes]: Invalid input: %v", err)
		return "", err
	}

	// Generate a new AES cipher block based on the secret key
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error(module, "", "[EncryptBytes]: Error creating AES cipher: %v", err)
		return "", errors.NewInternalServerError()
	}

	// Generate a random nonce (12 bytes for AES-GCM)
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		logger.Error(module, "", "[EncryptBytes]: Error generating nonce: %v", err)
		return "", err
	}

	// Create a new AES-GCM cipher stream
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error(module, "", "[EncryptBytes]: Error creating AES-GCM: %v", err)
		return "", errors.NewInternalServerError()
	}

	// Encrypt the data
	cipherText := aesGCM.Seal(nil, nonce, plainBytes, nil)

	// Combine the nonce and cipherText for transmission (nonce + cipherText)
	result := append(nonce, cipherText...)

	// Base64-encode the result to make it easily transmittable as a string
	encodedResult := base64.StdEncoding.EncodeToString(result)

	return encodedResult, nil
}

// DecryptBytes decrypts an AES-GCM encrypted string (base64 encoded) into a byte slice.
//
// Parameters:
//   - encryptedData string: The base64 encoded encrypted data (nonce + cipherText).
//   - secretKey []byte: The key used for decryption. It must be 32 bytes long for AES-256.
//
// Returns:
//   - []byte: The decrypted byte slice (plain data).
//   - error: Any error that occurs during decryption.
func DecryptBytes(encryptedData string, secretKey string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		logger.Error(module, "", "[DecryptBytes]: Error decoding base64 secret key: %v", err)
		return nil, errors.NewInternalServerError()
	} else if len(key) != 32 {
		err := errors.New(errors.ErrCodeInvalidInput, "secret key must be 32 bytes for AES-256")
		logger.Error(module, "", "[DecryptBytes]: Invalid input: %v", err)
		return nil, err
	}

	// Decode the base64 encoded data
	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		logger.Error(module, "", "[DecryptBytes]: Error decoding base64 data: %v", err)
		return nil, err
	}

	// Ensure the decoded data is at least the size of the nonce
	if len(decodedData) < 12 {
		err := errors.New(errors.ErrCodeInvalidInput, "invalid data length")
		logger.Error(module, "", "[DecryptBytes]: Invalid data length. It must include a nonce and cipher text.")
		return nil, err
	}

	// Extract the nonce (first 12 bytes)
	nonce := decodedData[:12]

	// Extract the cipherText (remaining bytes)
	cipherText := decodedData[12:]

	// Generate a new AES cipher block based on the secret key
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error(module, "", "[DecryptBytes]: Error creating AES cipher: %v", err)
		return nil, errors.NewInternalServerError()
	}

	// Create a new AES-GCM cipher stream
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		logger.Error(module, "", "[DecryptBytes]: Error creating AES-GCM: %v", err)
		return nil, errors.NewInternalServerError()
	}

	// Decrypt the cipherText using the nonce
	plainBytes, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		logger.Error(module, "", "[DecryptBytes]: Error decrypting data: %v", err)
		return nil, errors.NewInternalServerError()
	}

	return plainBytes, nil
}
