package errors

import "fmt"

// InputValidationError is the base error type for all user-related errors
type InputValidationError struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
	Field     string `json:"field,omitempty"`
}

func (e *InputValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("%s: %s", e.Field, e.Message)
	}
	return e.Message
}

// NewEmailFormatError creates an error for invalid email format
func NewEmailFormatError(email string) *InputValidationError {
	return &InputValidationError{
		Field:     "email",
		ErrorCode: ErrCodeInvalidEmail,
		Message:   fmt.Sprintf("Invalid email format: %s", email),
	}
}

// NewPasswordLengthError creates an error for invalid password length
func NewPasswordLengthError(length int) *InputValidationError {
	return &InputValidationError{
		Field:     "password",
		ErrorCode: ErrCodePasswordLength,
		Message:   fmt.Sprintf("Password must be at least %d characters", length),
	}
}

// NewDuplicateUserError creates an error for duplicate user
func NewDuplicateUserError(identifier string) *InputValidationError {
	return &InputValidationError{
		ErrorCode: ErrCodeDuplicateUser,
		Message:   fmt.Sprintf("User already exists with identifier: %s", identifier),
	}
}

// NewEmptyInputError creates an error for empty input fields
func NewEmptyInputError(field string) *InputValidationError {
	return &InputValidationError{
		Field:     field,
		ErrorCode: ErrCodeEmpty,
		Message:   fmt.Sprintf("%s cannot be empty", field),
	}
}
