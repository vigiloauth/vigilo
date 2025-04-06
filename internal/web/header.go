package web

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// ExtractClientBasicAuth extracts the client ID and client secret from the Authorization
// header of the request. The header must be in the form "Basic <base64 encoded
// client_id:client_secret>". If the header is invalid, an error is returned.
func ExtractClientBasicAuth(r *http.Request) (string, string, error) {
	authHeader := r.Header.Get(common.Authorization)
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "the authorization header is invalid or missing")
	}

	credentials, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "invalid credentials in the authorization header")
	}

	parts := strings.SplitN(string(credentials), ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "invalid credentials format in the authorization header")
	}

	return parts[0], parts[1], nil
}

// ExtractBearerToken extracts the Bearer token from the Authorization header of an HTTP request.
// It trims the "Bearer" prefix from the token and returns the token string.
//
// Parameters:
//
//	r: The HTTP request containing the Authorization header.
//
// Returns:
//
//	string: The extracted Bearer token.
//	error: An error if the Authorization header is missing or invalid.
func ExtractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get(common.Authorization)
	if authHeader == "" {
		err := errors.New(errors.ErrCodeMissingHeader, "authorization header is missing")
		return "", err
	}

	return strings.TrimPrefix(authHeader, common.Bearer), nil
}

// SetNoStoreHeader sets the Cache-Control header of an HTTP response to "no-store".
// This ensures that the response is not cached by the client or intermediary caches.
//
// Parameters:
//
//	w: The HTTP response writer to set the header on.
func SetNoStoreHeader(w http.ResponseWriter) {
	w.Header().Set(common.CacheControl, common.NoStore)
}
