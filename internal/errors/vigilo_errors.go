package errors

import (
	"context"
	"errors"
	"fmt"
)

// VigiloAuthError represents a standardized error structure
type VigiloAuthError struct {
	SystemCode       string   `json:"system_code"`
	ErrorCode        string   `json:"error"`
	ErrorDescription string   `json:"error_description"`
	ErrorDetails     string   `json:"error_details,omitempty"`
	WrappedErr       error    `json:"-"`
	Errors           *[]error `json:"errors,omitempty"`
	RedirectURL      string   `json:"redirect_url,omitempty"`
	ConsentURL       string   `json:"consent_url,omitempty"`
}

// Error implements the error interface
func (e *VigiloAuthError) Error() string {
	if e.ErrorDetails != "" {
		return fmt.Sprintf("%s: %s", e.ErrorDescription, e.ErrorDetails)
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
		SystemCode:       SystemErrorCodeMap[errCode],
		ErrorCode:        errCode,
		ErrorDescription: errorDescription,
	}
}

// NewInternalServerError creates a new error with default fields.
func NewInternalServerError() error {
	return &VigiloAuthError{
		SystemCode:       SystemErrorCodeMap[ErrCodeInternalServerError],
		ErrorCode:        ErrCodeInternalServerError,
		ErrorDescription: "An unexpected error occurred. Please try again later.",
	}
}

// NewConsentRequiredError returns a new VigiloAuthError when the user's consent is required
// for the requested scope. The error includes the consent URL.
func NewConsentRequiredError(url string) *VigiloAuthError {
	return &VigiloAuthError{
		ErrorCode:        ErrCodeConsentRequired,
		ErrorDescription: "user consent required for the requested scope(s)",
		ConsentURL:       url,
	}
}

func NewAccessDeniedError() *VigiloAuthError {
	return &VigiloAuthError{
		ErrorCode:        ErrCodeAccessDenied,
		ErrorDescription: "the resource owner denied the request",
	}
}

func NewSessionCreationError(err error) error {
	return Wrap(err, "", "failed to create new session")
}

func NewRequestValidationError(err error) error {
	return Wrap(err, "", "failed to validate request parameters")
}

func NewRequestBodyDecodingError(err error) error {
	return New(ErrCodeInvalidRequest, "missing one or more required fields in the request")
}

func NewMethodNotAllowedError(method string) error {
	return New(ErrCodeMethodNotAllowed, fmt.Sprintf("method not allowed: %s", method))
}

func NewMissingParametersError() error {
	return New(ErrCodeInvalidRequest, "missing one or more required parameters")
}

func NewInvalidSessionError() error {
	return &VigiloAuthError{
		ErrorCode:        ErrCodeInvalidSession,
		ErrorDescription: "unable to retrieve session data",
		ErrorDetails:     "session not found or expired",
	}
}

func NewClientAuthenticationError(err error) error {
	return Wrap(err, "", "failed to authenticate request")
}

func NewFormParsingError(err error) error {
	return Wrap(err, ErrCodeInvalidRequest, "unable to parse form")
}

func NewTimeoutError(err error) error {
	return Wrap(err, ErrCodeRequestTimeout, "the request timed out")
}

func NewContextCancelledError(err error) error {
	return Wrap(err, ErrCodeRequestCancelled, "the request was cancelled")
}

func NewContextError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return NewTimeoutError(err)
	} else {
		return NewContextCancelledError(err)
	}
}

func IsContextError(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
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

	vigiloError := &VigiloAuthError{}
	if e, ok := err.(*ErrorCollection); ok {
		vigiloError.ErrorCode = ErrCodeValidationError
		vigiloError.ErrorDescription = message
		vigiloError.Errors = e.Errors()
		vigiloError.ErrorDetails = "one or more validation errors occurred"
	} else if IsContextError(err) {
		return NewContextError(err)
	} else {
		vigiloError.ErrorCode = code
		vigiloError.ErrorDescription = message
		vigiloError.ErrorDetails = err.Error()
		vigiloError.WrappedErr = err
	}

	return vigiloError
}

// Unwrap returns the wrapped error
func (e *VigiloAuthError) Unwrap() error {
	return e.WrappedErr
}

// Code extracts the error code from a VigiloAuthError
func Code(err error) string {
	if err == nil {
		return ""
	}

	if vigiloErr, ok := err.(*VigiloAuthError); ok {
		return vigiloErr.ErrorCode
	}

	var vigiloErr *VigiloAuthError
	if errors.As(err, &vigiloErr) {
		return vigiloErr.ErrorCode
	}

	return ""
}
