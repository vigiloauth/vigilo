package utils

import (
	"encoding/json"
	"net/http"

	"github.com/vigiloauth/vigilo/internal/errors"
)

func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		panic(err)
	}
}

func WriteError(w http.ResponseWriter, err error) {
	var status int
	var response any

	switch e := err.(type) {
	case *errors.ErrorCollection:
		status = http.StatusBadRequest
		response = ErrorResponse{
			ErrorCode:   errors.ErrCodeValidationError,
			Description: "One or more validation errors occurred.",
			Errors:      e.Errors(),
		}

	case *errors.AuthenticationError:
		switch e.ErrorCode {
		case errors.ErrCodeInvalidCredentials:
			status = http.StatusUnauthorized
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeInvalidCredentials,
				Description: e.Message,
				Error:       e.Error(),
			}
		case errors.ErrCodeAccountLocked:
			status = http.StatusLocked
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeAccountLocked,
				Description: e.Message,
				Error:       e.Error(),
			}

		}

	case *errors.InputValidationError:
		switch e.ErrorCode {
		case errors.ErrCodeDuplicateUser:
			status = http.StatusConflict
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeDuplicateUser,
				Description: e.Message,
				Error:       e.Error(),
			}
		case errors.ErrCodeUserNotFound:
			status = http.StatusNotFound
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeUserNotFound,
				Description: e.Message,
				Error:       e.Error(),
			}
		default:
			status = http.StatusBadRequest
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeValidationError,
				Description: e.Message,
				Error:       e.Error(),
			}
		}

	case *errors.TokenErrors:
		switch e.ErrorCode {
		case errors.ErrCodeTokenNotFound:
			status = http.StatusNotFound
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeTokenNotFound,
				Description: e.Message,
			}
		case errors.ErrCodeExpiredToken:
			status = http.StatusUnauthorized
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeExpiredToken,
				Description: e.Message,
			}
		case errors.ErrCodeTokenCreation:
			status = http.StatusInternalServerError
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeTokenCreation,
				Description: e.Message,
			}
		}

	case *errors.EmailError:
		switch e.ErrorCode {
		case errors.ErrCodeEmailDeliveryFailed:
			status = http.StatusInternalServerError
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeEmailDeliveryFailed,
				Description: e.Message,
			}
		case errors.ErrCodeEmailTemplateParseFailed:
			status = http.StatusBadRequest
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeEmailTemplateParseFailed,
				Description: e.Message,
			}
		case errors.ErrCodeTemplateRenderingFailed:
			status = http.StatusInternalServerError
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeTemplateRenderingFailed,
				Description: e.Message,
			}
		case errors.ErrCodeUnsupportedEncryptionType:
			status = http.StatusBadRequest
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeUnsupportedEncryptionType,
				Description: e.Message,
			}
		case errors.ErrCodeSMTPServerConnectionFailed:
			status = http.StatusBadGateway
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeSMTPServerConnectionFailed,
				Description: e.Message,
			}
		case errors.ErrCodeTLSConnectionFailed:
			status = http.StatusBadGateway
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeTLSConnectionFailed,
				Description: e.Message,
			}
		case errors.ErrCodeClientCreationFailed:
			status = http.StatusInternalServerError
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeClientCreationFailed,
				Description: e.Message,
			}
		case errors.ErrCodeStartTLSFailed:
			status = http.StatusBadGateway
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeStartTLSFailed,
				Description: e.Message,
			}
		case errors.ErrCodeSMTPAuthenticationFailed:
			status = http.StatusUnauthorized
			response = ErrorResponse{
				ErrorCode:   errors.ErrCodeSMTPAuthenticationFailed,
				Description: e.Message,
			}
		}

	default:
		status = http.StatusInternalServerError
		response = ErrorResponse{
			ErrorCode:   errors.ErrCodeInternalServerError,
			Description: err.Error(),
		}
	}

	WriteJSON(w, status, response)
}

type ErrorResponse struct {
	ErrorCode   string   `json:"error_code"`
	Description string   `json:"description"`
	Error       string   `json:"error,omitempty"`
	Errors      *[]error `json:"errors,omitempty"`
}
