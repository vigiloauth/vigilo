package errors

import "fmt"

// VigiloAuthError represents a standardized error structure
type VigiloAuthError struct {
	ErrorCode          string   `json:"error"`
	ErrorDescription   string   `json:"error_description"`
	Details            string   `json:"error_details,omitempty"`
	WrappedErr         error    `json:"-"`
	Errors             *[]error `json:"errors,omitempty"`
	OAuthLoginEndpoint string   `json:"login_url,omitempty"`
	ConsentURL         string   `json:"consent_url,omitempty"`
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

// NewInternalServerError creates a new error with default fields.
func NewInternalServerError() error {
	return &VigiloAuthError{
		ErrorCode:        ErrCodeInternalServerError,
		ErrorDescription: "An unexpected error occurred. Please try again later.",
	}
}

// NewLoginRequiredError returns a new VigiloAuthError when the user is not authenticated
// during the authorization code flow. The error includes the OAuth login endpoint URL.
func NewLoginRequiredError(url string) *VigiloAuthError {
	return &VigiloAuthError{
		ErrorCode:          ErrCodeLoginRequired,
		ErrorDescription:   "authentication required to continue the authorization flow",
		OAuthLoginEndpoint: url,
	}
}

// NewConsentRequiredError returns a new VigiloAuthError when the user's consent is required
// for the requested scope. The error includes the consent URL.
func NewConsentRequiredError(url string) *VigiloAuthError {
	return &VigiloAuthError{
		ErrorCode:        ErrCodeConsentRequired,
		ErrorDescription: "user consent required for the requested scope",
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
	return Wrap(err, ErrCodeInternalServerError, "failed to decode request body")
}

func NewMethodNotAllowedError(method string) error {
	return New(ErrCodeMethodNotAllowed, fmt.Sprintf("method not allowed: %s", method))
}

func NewInvalidSessionError() error {
	return &VigiloAuthError{
		ErrorCode:        ErrCodeInvalidSession,
		ErrorDescription: "unable to retrieve session data",
		Details:          "session not found or expired",
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
