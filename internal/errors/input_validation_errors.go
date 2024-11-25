package errors

import "fmt"

// InputValidationError is the base error type for all user-related errors
type InputValidationError struct {
	Message   string `json:"message"`
	Field     string `json:"field,omitempty"` // optional, only used when relevant
	ErrorCode string `json:"error_code"`
}

func (e *InputValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// Error codes for all validation errors
const (
	ErrCodeEmpty            = "EMPTY_FIELD"
	ErrCodePasswordLength   = "INVALID_LENGTH"
	ErrCodeMissingUppercase = "MISSING_UPPERCASE"
	ErrCodeMissingNumber    = "MISSING_NUMBER"
	ErrCodeMissingSymbol    = "MISSING_SYMBOL"
	ErrCodeInvalidEmail     = "INVALID_EMAIL_FORMAT"
	ErrCodeDuplicateUser    = "DUPLICATE_USER"
)

// NewEmailFormatError creates an error for invalid email format
func NewEmailFormatError(email string) error {
	return &InputValidationError{
		Field:     "email",
		ErrorCode: ErrCodeInvalidEmail,
		Message:   fmt.Sprintf("Invalid email format: %s", email),
	}
}

// NewPasswordLengthError creates an error for invalid password length
func NewPasswordLengthError(length int) error {
	return &InputValidationError{
		Field:     "password",
		ErrorCode: ErrCodePasswordLength,
		Message:   fmt.Sprintf("Password must be at least %d characters", length),
	}
}

// NewDuplicateUserError creates an error for duplicate user
func NewDuplicateUserError(identifier string) error {
	return &InputValidationError{
		ErrorCode: ErrCodeDuplicateUser,
		Message:   fmt.Sprintf("User already exists with identifier: %s", identifier),
	}
}

// NewEmptyInputError creates an error for empty input fields
func NewEmptyInputError(field string) error {
	return &InputValidationError{
		Field:     field,
		ErrorCode: ErrCodeEmpty,
		Message:   fmt.Sprintf("%s cannot be empty", field),
	}
}
