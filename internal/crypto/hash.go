package crypto

import (
	"github.com/google/uuid"
	"github.com/vigiloauth/vigilo/identity/config"
	"golang.org/x/crypto/bcrypt"
)

var logger = config.GetServerConfig().Logger()

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
		logger.Error("crypto", "HashString: Error hashing string: %v", err)
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
	logger.Warn("crypto", "CompareHash: Error comparing hashes")
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
	logger.Debug("crypto", "GenerateUUID: Generated UUID: %s", uuid)
	return uuid
}
