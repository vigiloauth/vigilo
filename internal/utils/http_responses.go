package utils

import (
	"encoding/json"
	"github.com/vigiloauth/vigilo/internal/users"
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

	switch e := err.(type) {
	case *users.EmailFormatError:
		status = http.StatusUnprocessableEntity
		response = ErrorResponse{
			Error:       "invalid_email_format",
			Description: e.Error(),
		}
	case *users.DuplicateUserError:
		status = http.StatusConflict
		response = ErrorResponse{
			Error:       "duplicate_user_error",
			Description: e.Error(),
		}
	case *users.PasswordLengthError:
		status = http.StatusUnprocessableEntity
		response = ErrorResponse{
			Error:       "password_length_error",
			Description: e.Error(),
		}
	case *users.EmptyInputError:
		status = http.StatusBadRequest
		response = ErrorResponse{
			Error:       "empty_input_error",
			Description: e.Error(),
		}
	default:
		status = http.StatusInternalServerError
		response = ErrorResponse{
			Error:       "internal_server_error",
			Description: e.Error(),
		}
	}

	WriteJSON(w, status, response)
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}
