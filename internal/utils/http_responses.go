package utils

import (
	"encoding/json"
	"github.com/vigiloauth/vigilo/internal/errors"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func WriteError(w http.ResponseWriter, err error) {
	var status int
	var response interface{}

	if validationError, ok := err.(*errors.InputValidationError); ok {
		switch validationError.ErrorCode {
		case errors.ErrCodeEmpty:
			status = http.StatusBadRequest
			response = validationError
		case errors.ErrCodePasswordLength:
			status = http.StatusBadRequest
			response = validationError
		case errors.ErrCodeMissingUppercase:
			status = http.StatusBadRequest
			response = validationError
		case errors.ErrCodeMissingNumber:
			status = http.StatusBadRequest
			response = validationError
		case errors.ErrCodeMissingSymbol:
			status = http.StatusBadRequest
			response = validationError
		case errors.ErrCodeInvalidEmail:
			status = http.StatusBadRequest
			response = validationError
		case errors.ErrCodeDuplicateUser:
			status = http.StatusConflict
			response = validationError
		default:
			status = http.StatusInternalServerError
			response = ErrorResponse{
				Error:       "INTERNAL_SERVER_ERROR",
				Description: validationError.Error(),
			}
		}
	}

	WriteJSON(w, status, response)
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}
