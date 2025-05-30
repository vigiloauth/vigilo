package web

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
)

// ExtractClientBasicAuth extracts the client ID and client secret from the Authorization
// header of the request. The header must be in the form "Basic <base64 encoded
// client_id:client_secret>". If the header is invalid, an error is returned.
func ExtractClientBasicAuth(r *http.Request) (string, string, error) {
	authHeader := r.Header.Get(constants.AuthorizationHeader)
	if !strings.HasPrefix(authHeader, constants.BasicAuthHeader) {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "the authorization header is invalid or missing")
	}

	credentials, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "invalid credentials in the authorization header")
	}

	const subStrCount int = 2
	parts := strings.SplitN(string(credentials), ":", subStrCount)
	if len(parts) != subStrCount {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "invalid credentials format in the authorization header")
	}

	return parts[0], parts[1], nil
}

// ExtractBearerToken extracts the Bearer token from the Authorization header of an HTTP request.
// It trims the "Bearer" prefix from the token and returns the token string.
//
// Parameters:
//   - r *http.Request: The HTTP request containing the Authorization header.
//
// Returns:
//   - string: The extracted Bearer token.
//   - error: An error if the Authorization header is missing or invalid.
func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get(constants.AuthorizationHeader)
	if authHeader == "" {
		err := errors.New(errors.ErrCodeMissingHeader, "authorization header is missing")
		return "", err
	}

	lowercaseHeader := strings.ToLower(authHeader)
	if !strings.HasPrefix(lowercaseHeader, "bearer ") {
		err := errors.New(errors.ErrCodeInvalidFormat, "authorization header must start with Bearer")
		return "", err
	}

	return authHeader[7:], nil
}

// SetNoStoreHeader sets the Cache-Control header of an HTTP response to "no-store".
// This ensures that the response is not cached by the client or intermediary caches.
//
// Parameters:
//
//	w: The HTTP response writer to set the header on.
func SetNoStoreHeader(w http.ResponseWriter) {
	w.Header().Set(constants.CacheControlHeader, constants.NoStoreHeader)
}
