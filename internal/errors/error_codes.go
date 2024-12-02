package errors

const (
	ErrCodeEmpty               = "EMPTY_FIELD"
	ErrCodePasswordLength      = "INVALID_LENGTH"
	ErrCodeMissingUppercase    = "MISSING_UPPERCASE"
	ErrCodeMissingNumber       = "MISSING_NUMBER"
	ErrCodeMissingSymbol       = "MISSING_SYMBOL"
	ErrCodeInvalidEmail        = "INVALID_EMAIL_FORMAT"
	ErrCodeDuplicateUser       = "DUPLICATE_USER"
	ErrCodeValidationError     = "VALIDATION_ERROR"
	ErrCodeInternalServerError = "INTERNAL_SERVER_ERROR"
)
