package web

import (
	"encoding/json"
	"net/http"

	"github.com/vigiloauth/vigilo/internal/errors"
)

// DecodeJSONRequest decodes the JSON request body into the provided generic type T.
// It reads the request body, attempts to decode it into the specified type, and returns
// a pointer to the decoded object. If decoding fails, it returns an error wrapped with
// an internal server error code.
//
// Parameters:
//
//   - w: The HTTP response writer.
//   - r: The HTTP request containing the JSON body to decode.
//
// Returns:
//
//   - A pointer to the decoded object of type T, or an error if decoding fails.
func DecodeJSONRequest[T any](w http.ResponseWriter, r *http.Request) (*T, error) {
	var request T
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to decode request")
	}

	return &request, nil
}
