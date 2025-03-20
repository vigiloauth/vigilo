package errors

import (
	"fmt"
)

// VigiloAuthError represents a standardized error structure
type VigiloAuthError struct {
	ErrorCode        string   `json:"error"`
	ErrorDescription string   `json:"error_description"`
	Details          string   `json:"error_details,omitempty"`
	WrappedErr       error    `json:"-"`
	Errors           *[]error `json:"errors,omitempty"`
}

// Error implements the error interface
func (e *VigiloAuthError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s", e.ErrorDescription, e.Details)
	}
	return e.ErrorDescription
}

// New creates a new error with the given code and message
//
// Parameters:
//
//	errCode string: The error code
//	errorDescription string: A brief description of the error.
func New(errCode string, errorDescription string) error {
	return &VigiloAuthError{
		ErrorCode:        errCode,
		ErrorDescription: errorDescription,
	}
}

func NewInternalServerError() error {
	return &VigiloAuthError{
		ErrorCode:        ErrCodeInternalServerError,
		ErrorDescription: "An unexpected error occurred. Please try again later.",
	}
}

// Wrap wraps an existing error with additional context
// If no code is provided, it will extract it from the wrapper error.
func Wrap(err error, code string, message string) error {
	if err == nil {
		return nil
	}

	if code == "" {
		if vigiloErr, ok := err.(*VigiloAuthError); ok {
			code = vigiloErr.ErrorCode
		}
	}

	return &VigiloAuthError{
		ErrorCode:        code,
		ErrorDescription: message,
		Details:          err.Error(),
		WrappedErr:       err,
	}
}

// Unwrap returns the wrapped error
func (e *VigiloAuthError) Unwrap() error {
	return e.WrappedErr
}
