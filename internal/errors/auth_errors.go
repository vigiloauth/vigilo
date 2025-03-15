package errors

type AuthenticationError struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
}

func (e *AuthenticationError) Error() string {
	return e.Message
}

// NewAccountLockedError creates an error when an account is locked
func NewAccountLockedError() *AuthenticationError {
	return &AuthenticationError{
		ErrorCode: ErrCodeAccountLocked,
		Message:   "Account is locked due to too many failed login attempts",
	}
}

// NewInvalidCredentials creates an error for invalid credentials
func NewInvalidCredentialsError() *AuthenticationError {
	return &AuthenticationError{
		ErrorCode: ErrCodeInvalidCredentials,
		Message:   "Invalid credentials",
	}
}

func NewUnauthorizedError(message string) *AuthenticationError {
	return &AuthenticationError{
		ErrorCode: ErrCodeUnauthorized,
		Message:   message,
	}
}
