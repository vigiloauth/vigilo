package utils

import "golang.org/x/crypto/bcrypt"

// HashString takes a plain text password and returns a hashed version of it using bcrypt.
func HashString(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CompareHash compares a plain text password with a hashed password and returns true if they match.
func CompareHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
