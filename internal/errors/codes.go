package errors

import "net/http"

// Error codes
const (
	// Validation errors
	ErrCodeEmptyInput            = "empty_field"
	ErrCodeInvalidPasswordFormat = "invalid_password_format"
	ErrCodePasswordLength        = "invalid_password_length"
	ErrCodeMissingUppercase      = "missing_required_uppercase"
	ErrCodeMissingNumber         = "missing_required_number"
	ErrCodeMissingSymbol         = "missing_required_symbol"
	ErrCodeInvalidEmail          = "invalid_email_format"
	ErrCodeInvalidFormat         = "invalid_format"
	ErrCodeValidationError       = "validation_error"
	ErrCodeMissingHeader         = "missing_header"
	ErrCodeInvalidContentType    = "invalid_content_type"
	ErrCodeInvalidRequest        = "invalid_request"
	ErrCodeMethodNotAllowed      = "method_not_allowed"
	ErrCodeBadRequest            = "bad_request"

	// User errors
	ErrCodeDuplicateUser      = "duplicate_user"
	ErrCodeUserNotFound       = "user_not_found"
	ErrCodeInvalidCredentials = "invalid_credentials"
	ErrCodeAccountLocked      = "account_locked"
	ErrCodeUnauthorized       = "unauthorized"
	ErrCodeLoginRequired      = "login_required"
	ErrCodeConsentRequired    = "consent_required"

	// Token errors
	ErrCodeTokenNotFound = "token_not_found"
	ErrCodeExpiredToken  = "token_expired"
	ErrCodeTokenCreation = "token_creation"
	ErrCodeInvalidToken  = "invalid_token"
	ErrCodeTokenParsing  = "token_parsing"

	// Email errors
	ErrCodeEmailDeliveryFailed        = "email_delivery_failed"
	ErrCodeEmailTemplateParseFailed   = "email_template_parse_failed"
	ErrCodeTemplateRenderingFailed    = "template_rendering_failed"
	ErrCodeUnsupportedEncryptionType  = "unsupported_encryption_type"
	ErrCodeSMTPServerConnectionFailed = "smtp_server_connection_failed"
	ErrCodeTLSConnectionFailed        = "tls_connection_failed"
	ErrCodeSMTPClientCreationFailed   = "smtp_client_creation_failed"
	ErrCodeStartTLSFailed             = "starttls_failed"
	ErrCodeSMTPAuthenticationFailed   = "smtp_authentication_failed"
	ErrCodeSMTPServerError            = "smtp_server_error"

	// Client errors
	ErrCodeInvalidClient          = "invalid_client"
	ErrCodeInvalidGrant           = "invalid_grant"
	ErrCodeInvalidRedirectURI     = "invalid_redirect_uri"
	ErrCodeInvalidScope           = "invalid_scope"
	ErrCodeClientSecretNotAllowed = "client_secret_not_allowed"
	ErrCodeClientNotFound         = "client_not_found"
	ErrCodeDuplicateClient        = "duplicate_client"
	ErrCodeInvalidResponseType    = "invalid_response_type"
	ErrCodeUnauthorizedClient     = "unauthorized_client"
	ErrCodeUnsupportedGrantType   = "unsupported_grant_type"
	ErrCodeAccessDenied           = "access_denied"

	// Session errors
	ErrCodeDuplicateSession = "duplicate_session"
	ErrCodeSessionNotFound  = "session_not_found"

	// Middleware Errors
	ErrCodeRequestLimitExceeded = "request_limit_exceeded"

	// System errors
	ErrCodeInternalServerError = "internal_server_error"
)

// HTTP status code mappings
var statusCodeMap = map[string]int{
	// 400 Bad Request
	ErrCodeEmptyInput:                http.StatusBadRequest,
	ErrCodeMissingNumber:             http.StatusBadRequest,
	ErrCodeMissingSymbol:             http.StatusBadRequest,
	ErrCodeMissingUppercase:          http.StatusBadRequest,
	ErrCodeInvalidPasswordFormat:     http.StatusBadRequest,
	ErrCodePasswordLength:            http.StatusBadRequest,
	ErrCodeInvalidEmail:              http.StatusBadRequest,
	ErrCodeValidationError:           http.StatusBadRequest,
	ErrCodeEmailTemplateParseFailed:  http.StatusBadRequest,
	ErrCodeUnsupportedEncryptionType: http.StatusBadRequest,
	ErrCodeMissingHeader:             http.StatusBadRequest,
	ErrCodeClientSecretNotAllowed:    http.StatusBadRequest,
	ErrCodeInvalidResponseType:       http.StatusBadRequest,
	ErrCodeInvalidContentType:        http.StatusBadRequest,
	ErrCodeUnsupportedGrantType:      http.StatusBadRequest,
	ErrCodeInvalidRequest:            http.StatusBadRequest,
	ErrCodeBadRequest:                http.StatusBadRequest,

	// 401 Unauthorized
	ErrCodeInvalidCredentials:       http.StatusUnauthorized,
	ErrCodeInvalidClient:            http.StatusUnauthorized,
	ErrCodeUnauthorized:             http.StatusUnauthorized,
	ErrCodeExpiredToken:             http.StatusUnauthorized,
	ErrCodeInvalidToken:             http.StatusUnauthorized,
	ErrCodeSMTPAuthenticationFailed: http.StatusUnauthorized,
	ErrCodeTokenParsing:             http.StatusUnauthorized,
	ErrCodeLoginRequired:            http.StatusUnauthorized,
	ErrCodeConsentRequired:          http.StatusUnauthorized,

	// 404 Not Found
	ErrCodeUserNotFound:    http.StatusNotFound,
	ErrCodeTokenNotFound:   http.StatusNotFound,
	ErrCodeClientNotFound:  http.StatusNotFound,
	ErrCodeSessionNotFound: http.StatusNotFound,

	// 403 Forbidden
	ErrCodeInvalidRedirectURI: http.StatusForbidden,
	ErrCodeUnauthorizedClient: http.StatusForbidden,
	ErrCodeInvalidGrant:       http.StatusForbidden,
	ErrCodeInvalidScope:       http.StatusForbidden,
	ErrCodeAccessDenied:       http.StatusForbidden,

	// 409 Conflict
	ErrCodeDuplicateUser:    http.StatusConflict,
	ErrCodeDuplicateClient:  http.StatusConflict,
	ErrCodeDuplicateSession: http.StatusConflict,

	// 422 Unprocessable Entity
	ErrCodeInvalidFormat: http.StatusUnprocessableEntity,

	// 423 Locked
	ErrCodeAccountLocked: http.StatusLocked,

	// 424 Failed Dependency
	ErrCodeEmailDeliveryFailed: http.StatusFailedDependency,

	// 500 Internal Server Error
	ErrCodeInternalServerError:      http.StatusInternalServerError,
	ErrCodeTokenCreation:            http.StatusInternalServerError,
	ErrCodeTemplateRenderingFailed:  http.StatusInternalServerError,
	ErrCodeSMTPClientCreationFailed: http.StatusInternalServerError,

	// 502 Bad Gateway
	ErrCodeSMTPServerConnectionFailed: http.StatusBadGateway,
	ErrCodeTLSConnectionFailed:        http.StatusBadGateway,
	ErrCodeStartTLSFailed:             http.StatusBadGateway,
	ErrCodeSMTPServerError:            http.StatusBadGateway,

	// 429 Too Many Requests
	ErrCodeRequestLimitExceeded: http.StatusTooManyRequests,

	// 405 Method Not Allowed
	ErrCodeMethodNotAllowed: http.StatusMethodNotAllowed,
}

// StatusCode returns the HTTP status code associated with the error code
func StatusCode(errorCode string) int {
	if status, exists := statusCodeMap[errorCode]; exists {
		return status
	}
	return http.StatusInternalServerError // Default status
}
