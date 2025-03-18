package errors

import "fmt"

// VigiloAuthError represents a standardized error structure
type VigiloAuthError struct {
	ErrorCode  string   `json:"error_code"`
	Message    string   `json:"message"`
	Details    string   `json:"details,omitempty"`
	WrappedErr error    `json:"-"`
	Errors     *[]error `json:"errors,omitempty"`
}

// Error implements the error interface
func (e *VigiloAuthError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s", e.Message, e.Details)
	}
	return e.Message
}

// New creates a new error with the given code and message
func New(code string, message string) error {
	return &VigiloAuthError{
		ErrorCode: code,
		Message:   message,
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
		ErrorCode:  code,
		Message:    message,
		Details:    err.Error(),
		WrappedErr: err,
	}
}

// Unwrap returns the wrapped error
func (e *VigiloAuthError) Unwrap() error {
	return e.WrappedErr
}
