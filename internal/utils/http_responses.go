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

// errorMapping defines the status code and error code for different error types
type errorMapping struct {
	StatusCode  int
	Description string
}

func getErrorMapping(err error) (int, ErrorResponse) {
	// Default error response
	defaultResponse := ErrorResponse{
		ErrorCode:   errors.ErrCodeInternalServerError,
		Description: err.Error(),
	}

	// Error collection handling (validation errors)
	if e, ok := err.(*errors.ErrorCollection); ok {
		return http.StatusBadRequest, ErrorResponse{
			ErrorCode:   errors.ErrCodeValidationError,
			Description: "One or more validation errors occurred.",
			Errors:      e.Errors(),
		}
	}

	// Define mappings by error type and code
	mappings := map[string]map[string]errorMapping{
		"AuthenticationError": {
			errors.ErrCodeInvalidCredentials: {http.StatusUnauthorized, ""},
			errors.ErrCodeAccountLocked:      {http.StatusLocked, ""},
			errors.ErrCodeUnauthorized:       {http.StatusUnauthorized, ""},
		},
		"InputValidationError": {
			errors.ErrCodeDuplicateUser: {http.StatusConflict, ""},
			errors.ErrCodeUserNotFound:  {http.StatusNotFound, ""},
			"default":                   {http.StatusBadRequest, ""},
		},
		"TokenErrors": {
			errors.ErrCodeTokenNotFound: {http.StatusNotFound, ""},
			errors.ErrCodeExpiredToken:  {http.StatusUnauthorized, ""},
			errors.ErrCodeTokenCreation: {http.StatusInternalServerError, ""},
			errors.ErrCodeInvalidToken:  {http.StatusUnauthorized, ""},
		},
		"EmailError": {
			errors.ErrCodeEmailDeliveryFailed:        {http.StatusInternalServerError, ""},
			errors.ErrCodeEmailTemplateParseFailed:   {http.StatusBadRequest, ""},
			errors.ErrCodeTemplateRenderingFailed:    {http.StatusInternalServerError, ""},
			errors.ErrCodeUnsupportedEncryptionType:  {http.StatusBadRequest, ""},
			errors.ErrCodeSMTPServerConnectionFailed: {http.StatusBadGateway, ""},
			errors.ErrCodeTLSConnectionFailed:        {http.StatusBadGateway, ""},
			errors.ErrCodeClientCreationFailed:       {http.StatusInternalServerError, ""},
			errors.ErrCodeStartTLSFailed:             {http.StatusBadGateway, ""},
			errors.ErrCodeSMTPAuthenticationFailed:   {http.StatusUnauthorized, ""},
		},
	}

	// Handle each error type
	switch e := err.(type) {
	case *errors.AuthenticationError:
		if mapping, ok := mappings["AuthenticationError"][e.ErrorCode]; ok {
			return mapping.StatusCode, ErrorResponse{
				ErrorCode:   e.ErrorCode,
				Description: e.Message,
				Error:       e.Error(),
			}
		}
	case *errors.InputValidationError:
		mapping, ok := mappings["InputValidationError"][e.ErrorCode]
		if !ok {
			mapping = mappings["InputValidationError"]["default"]
		}
		return mapping.StatusCode, ErrorResponse{
			ErrorCode:   e.ErrorCode,
			Description: e.Message,
			Error:       e.Error(),
		}
	case *errors.TokenErrors:
		if mapping, ok := mappings["TokenErrors"][e.ErrorCode]; ok {
			return mapping.StatusCode, ErrorResponse{
				ErrorCode:   e.ErrorCode,
				Description: e.Message,
			}
		}
	case *errors.EmailError:
		if mapping, ok := mappings["EmailError"][e.ErrorCode]; ok {
			return mapping.StatusCode, ErrorResponse{
				ErrorCode:   e.ErrorCode,
				Description: e.Message,
			}
		}
	}

	return http.StatusInternalServerError, defaultResponse
}

func WriteError(w http.ResponseWriter, err error) {
	status, response := getErrorMapping(err)
	WriteJSON(w, status, response)
}

type ErrorResponse struct {
	ErrorCode   string   `json:"error_code"`
	Description string   `json:"description"`
	Error       string   `json:"error,omitempty"`
	Errors      *[]error `json:"errors,omitempty"`
}
