package errors

import "fmt"

const (
	ErrCodeEmpty                      = "EMPTY_FIELD"
	ErrCodeInvalidPasswordFormat      = "INVALID_PASSWORD_FORMAT"
	ErrCodePasswordLength             = "INVALID_PASSWORD_LENGTH"
	ErrCodeMissingUppercase           = "MISSING_UPPERCASE"
	ErrCodeMissingNumber              = "MISSING_NUMBER"
	ErrCodeMissingSymbol              = "MISSING_SYMBOL"
	ErrCodeInvalidEmail               = "INVALID_EMAIL_FORMAT"
	ErrCodeDuplicateUser              = "DUPLICATE_USER"
	ErrCodeValidationError            = "VALIDATION_ERROR"
	ErrCodeInternalServerError        = "INTERNAL_SERVER_ERROR"
	ErrCodeUserNotFound               = "USER_NOT_FOUND"
	ErrCodeInvalidCredentials         = "INVALID_CREDENTIALS"
	ErrCodeAccountLocked              = "ACCOUNT_LOCKED"
	ErrCodeInvalidFormat              = "INVALID_FORMAT"
	ErrCodeEmailDeliveryFailed        = "EMAIL_DELIVERY_FAILED"
	ErrCodeEmailTemplateParseFailed   = "EMAIL_TEMPLATE_PARSE_FAILED"
	ErrCodeTemplateRenderingFailed    = "TEMPLATE_RENDERING_FAILED"
	ErrCodeUnsupportedEncryptionType  = "UNSUPPORTED_ENCRYPTION_TYPE"
	ErrCodeSMTPServerConnectionFailed = "SMTP_SERVER_CONNECTION_FAILED"
	ErrCodeTLSConnectionFailed        = "TLS_CONNECTION_FAILED"
	ErrCodeClientCreationFailed       = "CLIENT_CREATION_FAILED"
	ErrCodeStartTLSFailed             = "STARTTLS_FAILED"
	ErrCodeSMTPAuthenticationFailed   = "SMTP_AUTHENTICATION_FAILED"
	ErrCodeTokenNotFound              = "TOKEN_NOT_FOUND"
	ErrCodeExpiredToken               = "TOKEN_EXPIRED"
	ErrCodeTokenCreation              = "TOKEN_GENERATION"
	ErrCodeInvalidToken               = "INVALID_TOKEN"
	ErrCodeUnauthorized               = "UNAUTHORIZED"
)

func Wrap(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}
