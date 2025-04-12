package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"github.com/google/uuid"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	"golang.org/x/crypto/bcrypt"
)

var logger = config.GetServerConfig().Logger()

const module = "Crypto"

// HashString takes a plain text string and returns a hashed
// version of it using bcrypt with the default cost.
//
// Parameters:
//
//	plainStr string: The string to be encrypted.
//
// Returns:
//
//	string: The encrypted string.
//	error: Error if an error occurs hashing the string.
func HashString(plainStr string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainStr), bcrypt.DefaultCost)
	if err != nil {
		logger.Error(module, "HashString: Error hashing string: %v", err)
		return "", err
	}
	return string(hash), nil
}

// CompareHash compares a plain text string with a hashed
// string and returns true if they match.
//
// Parameters:
//
//	plainStr string: The plain text string.
//	hashStr string: The encrypted string.
//
// Returns:
//
//	bool: True if they match, otherwise false.
func CompareHash(plainStr, hashStr string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashStr), []byte(plainStr))
	logger.Warn(module, "CompareHash: Error comparing hashes")
	return err == nil
}

// GenerateUUID generates a new universally unique identifier (UUID) as a string.
// It uses the uuid package to create a version 4 UUID, which is a randomly generated UUID.
//
// Returns:
//
//   - string: A string representation of the generated UUID.
func GenerateUUID() string {
	uuid := uuid.New().String()
	logger.Debug(module, "GenerateUUID: Generated UUID: [%s]", common.TruncateSensitive(uuid))
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
