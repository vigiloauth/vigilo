package utils

import "golang.org/x/crypto/bcrypt"

// HashPassword takes a plain text password and returns a hashed version of it using bcrypt.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// ComparePasswordHash compares a plain text password with a hashed password and returns true if they match.
func ComparePasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
