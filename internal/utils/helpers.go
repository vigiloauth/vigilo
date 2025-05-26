package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"golang.org/x/crypto/bcrypt"
)

// KeysToSlice converts the keys of a map to slice.
//
// Parameters:
//   - input map[K]V: The map to extract the keys from.
//
// Returns:
//   - []K: A slice containing the keys from the input map.
func KeysToSlice[K comparable, V any](input map[K]V) []K {
	keys := make([]K, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}

	return keys
}

func IsSubset(subset, set []string) bool {
	m := make(map[string]struct{})
	for _, s := range set {
		m[s] = struct{}{}
	}
	for _, s := range subset {
		if _, ok := m[s]; !ok {
			return false
		}
	}
	return true
}

// contains checks if a slice contains a specific element.
func Contains[T comparable](slice []T, element T) bool {
	return slices.Contains(slice, element)
}

// Helper to check if a slice of space-separated response type strings contains a specific component (e.g., "code", "id_token", "token").
func ContainsResponseType(responseTypes []string, component string) bool {
	for _, responseTypeCombo := range responseTypes {
		components := strings.Fields(responseTypeCombo)
		if slices.Contains(components, component) {
			return true
		}
	}

	return false
}

// checks if a string contains a wildcard
func ContainsWildcard(uri string) bool {
	return strings.Contains(uri, "*")
}

// isLoopbackIP checks if the given IP is a loopback address.
func IsLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func ValidateRedirectURIScheme(parsedURL *url.URL) error {
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" && !strings.HasPrefix(parsedURL.Scheme, "custom") {
		return errors.New(
			errors.ErrCodeInvalidRedirectURI, "invalid scheme, must be 'https' or 'http' for localhost or 'custom' for mobile",
		)
	}

	return nil
}

func ParseURI(uri string) (*url.URL, error) {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRedirectURI, "invalid redirect URI format")
	}

	if parsedURL.Fragment != "" {
		return nil, errors.New(errors.ErrCodeInvalidRedirectURI, "fragments are not allowed in the redirect URI")
	}

	return parsedURL, nil
}

func ValidatePublicURIScheme(parsedURL *url.URL) error {
	if parsedURL.Scheme == "http" && parsedURL.Host != "localhost" {
		return errors.New(errors.ErrCodeInvalidRedirectURI, "'http' scheme is only allowed for 'localhost'")
	}

	if parsedURL.Scheme == "https" && parsedURL.Host == "localhost" {
		return errors.New(
			errors.ErrCodeInvalidRedirectURI,
			"'https' scheme is not allowed for for public clients using 'localhost'",
		)
	}

	return nil
}

func ValidateConfidentialURIScheme(parsedURL *url.URL) error {
	if strings.Contains(parsedURL.Host, "*") {
		return errors.New(errors.ErrCodeInvalidRedirectURI, "wildcards are not allowed for confidential clients")
	}

	return nil
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
