package web

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/internal/errors"
)

// ExtractBasicAuth extracts the client ID and client secret from the Authorization
// header of the request. The header must be in the form "Basic <base64 encoded
// client_id:client_secret>". If the header is invalid, an error is returned.
func ExtractBasicAuth(r *http.Request) (string, string, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "invalid authorization header")
	}

	credentials, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "invalid credentials")
	}

	parts := strings.SplitN(string(credentials), ":", 2)
	if len(parts) != 2 {
		return "", "", errors.New(errors.ErrCodeInvalidClient, "invalid credentials format")
	}

	return parts[0], parts[1], nil
}

// ExtractIDFromURL extracts the ID from the URL. The ID is the last but one part of the URL.
// If the URL is invalid, an error is returned.
func ExtractIDFromURL(w http.ResponseWriter, r *http.Request) (string, error) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 3 {
		return "", errors.New(errors.ErrCodeInvalidRequest, "invalid URL")
	}
	return parts[len(parts)-2], nil
}
