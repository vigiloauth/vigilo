package errors

const (
	ErrCodeEmpty                 = "EMPTY_FIELD"
	ErrCodeInvalidPasswordFormat = "INVALID_PASSWORD_FORMAT"
	ErrCodePasswordLength        = "INVALID_PASSWORD_LENGTH"
	ErrCodeMissingUppercase      = "MISSING_UPPERCASE"
	ErrCodeMissingNumber         = "MISSING_NUMBER"
	ErrCodeMissingSymbol         = "MISSING_SYMBOL"
	ErrCodeInvalidEmail          = "INVALID_EMAIL_FORMAT"
	ErrCodeDuplicateUser         = "DUPLICATE_USER"
	ErrCodeValidationError       = "VALIDATION_ERROR"
	ErrCodeInternalServerError   = "INTERNAL_SERVER_ERROR"
	ErrCodeUserNotFound          = "USER_NOT_FOUND"
	ErrCodeInvalidCredentials    = "INVALID_CREDENTIALS"
)
