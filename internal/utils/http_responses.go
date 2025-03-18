package utils

import (
	"encoding/json"
	"net/http"

	"github.com/vigiloauth/vigilo/internal/errors"
)

// WriteJSON writes the provided data as JSON to the HTTP response writer.
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		panic(err)
	}
}

// WriteError writes an error as JSON response with appropriate HTTP status code
func WriteError(w http.ResponseWriter, err error) {
	if e, ok := err.(*errors.ErrorCollection); ok {
		err := errors.VigiloAuthError{
			ErrorCode: errors.ErrCodeValidationError,
			Message:   "One or more validation errors occurred",
			Errors:    e.Errors(),
		}
		WriteJSON(w, http.StatusBadRequest, err)
	} else if stdErr, ok := err.(*errors.VigiloAuthError); ok {
		statusCode := errors.StatusCode(stdErr.ErrorCode)
		WriteJSON(w, statusCode, stdErr)
	} else {
		genericErr := createGenericError(err)
		WriteJSON(w, http.StatusInternalServerError, genericErr)
	}
}

func createGenericError(err error) error {
	return errors.New(errors.ErrCodeInternalServerError, err.Error())
}
