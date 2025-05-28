package errors

import "net/http"

// Error codes
const (
	// Validation errors
	ErrCodeEmptyInput            string = "empty_field"
	ErrCodeInvalidPasswordFormat string = "invalid_password_format"
	ErrCodePasswordLength        string = "invalid_password_length"
	ErrCodeMissingUppercase      string = "missing_required_uppercase"
	ErrCodeMissingNumber         string = "missing_required_number"
	ErrCodeMissingSymbol         string = "missing_required_symbol"
	ErrCodeInvalidEmail          string = "invalid_email_format"
	ErrCodeInvalidFormat         string = "invalid_format"
	ErrCodeValidationError       string = "validation_error"
	ErrCodeMissingHeader         string = "missing_header"
	ErrCodeInvalidContentType    string = "invalid_content_type"
	ErrCodeInvalidRequest        string = "invalid_request"
	ErrCodeBadRequest            string = "bad_request"
	ErrCodeInvalidInput          string = "invalid_input"
	ErrCodeInvalidDate           string = "invalid_date"
	ErrCodeNotFound              string = "not_found"

	// User errors
	ErrCodeDuplicateUser       string = "duplicate_user"
	ErrCodeUserNotFound        string = "user_not_found"
	ErrCodeInvalidCredentials  string = "invalid_credentials"
	ErrCodeAccountLocked       string = "account_locked"
	ErrCodeUnauthorized        string = "unauthorized"
	ErrCodeLoginRequired       string = "login_required"
	ErrCodeConsentRequired     string = "consent_required"
	ErrCodeInsufficientRole    string = "insufficient_role"
	ErrCodeInteractionRequired string = "interaction_required"

	// Token errors
	ErrCodeTokenNotFound   string = "token_not_found"
	ErrCodeExpiredToken    string = "token_expired"
	ErrCodeTokenCreation   string = "token_creation"
	ErrCodeInvalidToken    string = "invalid_token"
	ErrCodeTokenParsing    string = "token_parsing"
	ErrCodeTokenEncryption string = "token_encrypt_failed"
	ErrCodeTokenDecryption string = "token_decrypt_failed"
	ErrCodeDuplicateToken  string = "duplicate_token"
	ErrCodeTokenSigning    string = "token_signing"

	// Email errors
	ErrCodeConnectionFailed    string = "connection_failed"
	ErrCodeEmailDeliveryFailed string = "delivery_failed"

	// Client errors
	ErrCodeInvalidClient             string = "invalid_client"
	ErrCodeInvalidGrant              string = "invalid_grant"
	ErrCodeInvalidRedirectURI        string = "invalid_redirect_uri"
	ErrCodeInsufficientScope         string = "insufficient_scope"
	ErrCodeClientSecretNotAllowed    string = "client_secret_not_allowed"
	ErrCodeClientNotFound            string = "client_not_found"
	ErrCodeDuplicateClient           string = "duplicate_client"
	ErrCodeInvalidResponseType       string = "invalid_response_type"
	ErrCodeUnauthorizedClient        string = "unauthorized_client"
	ErrCodeUnsupportedGrantType      string = "unsupported_grant_type"
	ErrCodeAccessDenied              string = "access_denied"
	ErrCodeInvalidClientMetadata     string = "invalid_client_metadata"
	ErrCodeRequestURINotSupported    string = "request_uri_not_supported"
	ErrCodeRequestObjectNotSupported string = "request_not_supported"

	// Session errors
	ErrCodeDuplicateSession string = "duplicate_session"
	ErrCodeSessionNotFound  string = "session_not_found"
	ErrCodeInvalidSession   string = "invalid_session"
	ErrCodeSessionExpired   string = "expired_session"

	// Middleware Errors
	ErrCodeRequestLimitExceeded string = "request_limit_exceeded"
	ErrCodeSessionCreation      string = "session_create_failed"
	ErrCodeSessionSave          string = "session_save_failed"

	// System errors
	ErrCodeInternalServerError string = "server_error"
	ErrCodeRequestTimeout      string = "request_timeout"
	ErrCodeRequestCancelled    string = "request_cancelled"
	ErrCodeResourceNotFound    string = "resource_not_found"
	ErrCodeMethodNotAllowed    string = "method_not_allowed"

	// Authorization Code Errors
	ErrCodeInvalidAuthorizationCode  string = "invalid_authorization_code"
	ErrCodeExpiredAuthorizationCode  string = "expired_authorization_code"
	ErrCodeAuthorizationCodeNotFound string = "code_not_found"

	// Encryption Errors
	ErrCodeHashingFailed          string = "hashing_failed"
	ErrCodeRandomGenerationFailed string = "random_generation_failed"
	ErrCodeEncryptionFailed       string = "encryption_failed"
	ErrCodeDecryptionFailed       string = "decryption_failed"
)

// HTTP status code mappings
var HTTPStatusCodeMap = map[string]int{
	// 400 Bad Request
	ErrCodeEmptyInput:                http.StatusBadRequest,
	ErrCodeMissingNumber:             http.StatusBadRequest,
	ErrCodeMissingSymbol:             http.StatusBadRequest,
	ErrCodeMissingUppercase:          http.StatusBadRequest,
	ErrCodeInvalidPasswordFormat:     http.StatusBadRequest,
	ErrCodePasswordLength:            http.StatusBadRequest,
	ErrCodeInvalidEmail:              http.StatusBadRequest,
	ErrCodeValidationError:           http.StatusBadRequest,
	ErrCodeMissingHeader:             http.StatusBadRequest,
	ErrCodeUnauthorizedClient:        http.StatusBadRequest,
	ErrCodeClientSecretNotAllowed:    http.StatusBadRequest,
	ErrCodeInvalidResponseType:       http.StatusBadRequest,
	ErrCodeInvalidContentType:        http.StatusBadRequest,
	ErrCodeUnsupportedGrantType:      http.StatusBadRequest,
	ErrCodeInvalidRequest:            http.StatusBadRequest,
	ErrCodeBadRequest:                http.StatusBadRequest,
	ErrCodeInvalidClientMetadata:     http.StatusBadRequest,
	ErrCodeInvalidGrant:              http.StatusBadRequest,
	ErrCodeInvalidInput:              http.StatusBadRequest,
	ErrCodeInvalidDate:               http.StatusBadRequest,
	ErrCodeInteractionRequired:       http.StatusBadRequest,
	ErrCodeLoginRequired:             http.StatusBadRequest,
	ErrCodeInvalidRedirectURI:        http.StatusBadRequest,
	ErrCodeRequestURINotSupported:    http.StatusBadRequest,
	ErrCodeRequestObjectNotSupported: http.StatusBadRequest,

	// 401 Unauthorized
	ErrCodeInvalidCredentials:       http.StatusUnauthorized,
	ErrCodeInvalidClient:            http.StatusUnauthorized,
	ErrCodeUnauthorized:             http.StatusUnauthorized,
	ErrCodeExpiredToken:             http.StatusUnauthorized,
	ErrCodeInvalidToken:             http.StatusUnauthorized,
	ErrCodeTokenParsing:             http.StatusUnauthorized,
	ErrCodeConsentRequired:          http.StatusUnauthorized,
	ErrCodeInvalidSession:           http.StatusUnauthorized,
	ErrCodeInvalidAuthorizationCode: http.StatusUnauthorized,
	ErrCodeExpiredAuthorizationCode: http.StatusUnauthorized,
	ErrCodeSessionExpired:           http.StatusUnauthorized,

	// 404 Not Found
	ErrCodeUserNotFound:              http.StatusNotFound,
	ErrCodeTokenNotFound:             http.StatusNotFound,
	ErrCodeClientNotFound:            http.StatusNotFound,
	ErrCodeSessionNotFound:           http.StatusNotFound,
	ErrCodeResourceNotFound:          http.StatusNotFound,
	ErrCodeAuthorizationCodeNotFound: http.StatusNotFound,
	ErrCodeNotFound:                  http.StatusNotFound,

	// 403 Forbidden
	ErrCodeAccessDenied:      http.StatusForbidden,
	ErrCodeInsufficientRole:  http.StatusForbidden,
	ErrCodeInsufficientScope: http.StatusForbidden,

	// 409 Conflict
	ErrCodeDuplicateUser:    http.StatusConflict,
	ErrCodeDuplicateClient:  http.StatusConflict,
	ErrCodeDuplicateSession: http.StatusConflict,

	// 422 Unprocessable Entity
	ErrCodeInvalidFormat: http.StatusUnprocessableEntity,

	// 423 Locked
	ErrCodeAccountLocked: http.StatusLocked,

	// 408 Request Timeout
	ErrCodeRequestTimeout:   http.StatusRequestTimeout,
	ErrCodeRequestCancelled: http.StatusRequestTimeout,

	// 500 Internal Server Error
	ErrCodeInternalServerError:    http.StatusInternalServerError,
	ErrCodeTokenCreation:          http.StatusInternalServerError,
	ErrCodeEmailDeliveryFailed:    http.StatusInternalServerError,
	ErrCodeSessionCreation:        http.StatusInternalServerError,
	ErrCodeSessionSave:            http.StatusInternalServerError,
	ErrCodeTokenEncryption:        http.StatusInternalServerError,
	ErrCodeTokenDecryption:        http.StatusInternalServerError,
	ErrCodeDuplicateToken:         http.StatusInternalServerError,
	ErrCodeTokenSigning:           http.StatusInternalServerError,
	ErrCodeHashingFailed:          http.StatusInternalServerError,
	ErrCodeRandomGenerationFailed: http.StatusInternalServerError,
	ErrCodeEncryptionFailed:       http.StatusInternalServerError,
	ErrCodeDecryptionFailed:       http.StatusInternalServerError,

	// 502 Bad Gateway
	ErrCodeConnectionFailed: http.StatusBadGateway,

	// 429 Too Many Requests
	ErrCodeRequestLimitExceeded: http.StatusTooManyRequests,

	// 405 Method Not Allowed
	ErrCodeMethodNotAllowed: http.StatusMethodNotAllowed,
}

const (
	prefix          string = "VIG"
	validationError string = "VAL"
	userError       string = "USR"
	tokenError      string = "TOK"
	emailError      string = "EML"
	clientError     string = "CLI"
	sessionError    string = "SES"
	middlewareError string = "MDW"
	systemError     string = "SYS"
	authzCodeError  string = "AUTH"
	cryptoError     string = "CRY"
)

var SystemErrorCodeMap = map[string]string{
	// Validation Errors
	ErrCodeEmptyInput:            prefix + validationError + "0001",
	ErrCodeInvalidPasswordFormat: prefix + validationError + "0002",
	ErrCodePasswordLength:        prefix + validationError + "0003",
	ErrCodeMissingUppercase:      prefix + validationError + "0004",
	ErrCodeMissingNumber:         prefix + validationError + "0005",
	ErrCodeMissingSymbol:         prefix + validationError + "0006",
	ErrCodeInvalidEmail:          prefix + validationError + "0007",
	ErrCodeInvalidFormat:         prefix + validationError + "0008",
	ErrCodeValidationError:       prefix + validationError + "0009",
	ErrCodeMissingHeader:         prefix + validationError + "0010",
	ErrCodeInvalidContentType:    prefix + validationError + "0011",
	ErrCodeInvalidRequest:        prefix + validationError + "0012",
	ErrCodeBadRequest:            prefix + validationError + "0013",
	ErrCodeInvalidInput:          prefix + validationError + "0014",
	ErrCodeInvalidDate:           prefix + validationError + "0015",
	ErrCodeNotFound:              prefix + validationError + "0016",

	// User Errors
	ErrCodeDuplicateUser:       prefix + userError + "0001",
	ErrCodeUserNotFound:        prefix + userError + "0002",
	ErrCodeInvalidCredentials:  prefix + userError + "0003",
	ErrCodeAccountLocked:       prefix + userError + "0004",
	ErrCodeUnauthorized:        prefix + userError + "0005",
	ErrCodeLoginRequired:       prefix + userError + "0006",
	ErrCodeConsentRequired:     prefix + userError + "0007",
	ErrCodeInsufficientRole:    prefix + userError + "0008",
	ErrCodeInteractionRequired: prefix + userError + "0009",

	// Token Errors
	ErrCodeTokenNotFound:   prefix + tokenError + "0001",
	ErrCodeExpiredToken:    prefix + tokenError + "0002",
	ErrCodeTokenCreation:   prefix + tokenError + "0003",
	ErrCodeInvalidToken:    prefix + tokenError + "0004",
	ErrCodeTokenParsing:    prefix + tokenError + "0005",
	ErrCodeTokenEncryption: prefix + tokenError + "0006",
	ErrCodeTokenDecryption: prefix + tokenError + "0007",
	ErrCodeDuplicateToken:  prefix + tokenError + "0008",
	ErrCodeTokenSigning:    prefix + tokenError + "0009",

	// Email Errors
	ErrCodeConnectionFailed:    prefix + emailError + "0001",
	ErrCodeEmailDeliveryFailed: prefix + emailError + "0002",

	// Client Errors
	ErrCodeInvalidClient:             prefix + clientError + "0001",
	ErrCodeInvalidGrant:              prefix + clientError + "0002",
	ErrCodeInvalidRedirectURI:        prefix + clientError + "0003",
	ErrCodeInsufficientScope:         prefix + clientError + "0004",
	ErrCodeClientSecretNotAllowed:    prefix + clientError + "0005",
	ErrCodeClientNotFound:            prefix + clientError + "0006",
	ErrCodeDuplicateClient:           prefix + clientError + "0007",
	ErrCodeInvalidResponseType:       prefix + clientError + "0008",
	ErrCodeUnauthorizedClient:        prefix + clientError + "0009",
	ErrCodeUnsupportedGrantType:      prefix + clientError + "0010",
	ErrCodeAccessDenied:              prefix + clientError + "0011",
	ErrCodeInvalidClientMetadata:     prefix + clientError + "0012",
	ErrCodeRequestURINotSupported:    prefix + clientError + "0013",
	ErrCodeRequestObjectNotSupported: prefix + clientError + "0014",

	// Session Errors
	ErrCodeDuplicateSession: prefix + sessionError + "0001",
	ErrCodeSessionNotFound:  prefix + sessionError + "0002",
	ErrCodeInvalidSession:   prefix + sessionError + "0003",
	ErrCodeSessionExpired:   prefix + sessionError + "0004",

	// Middleware Errors
	ErrCodeRequestLimitExceeded: prefix + middlewareError + "0001",
	ErrCodeSessionCreation:      prefix + middlewareError + "0002",
	ErrCodeSessionSave:          prefix + middlewareError + "0003",

	// System Errors
	ErrCodeInternalServerError: prefix + systemError + "0001",
	ErrCodeRequestTimeout:      prefix + systemError + "0002",
	ErrCodeRequestCancelled:    prefix + systemError + "0003",
	ErrCodeResourceNotFound:    prefix + systemError + "0004",
	ErrCodeMethodNotAllowed:    prefix + systemError + "0005",

	// Authorization Code Errors
	ErrCodeInvalidAuthorizationCode:  prefix + authzCodeError + "0001",
	ErrCodeExpiredAuthorizationCode:  prefix + authzCodeError + "0002",
	ErrCodeAuthorizationCodeNotFound: prefix + authzCodeError + "0003",

	// Crypto Errors
	ErrCodeHashingFailed:          prefix + cryptoError + "0001",
	ErrCodeRandomGenerationFailed: prefix + cryptoError + "0002",
	ErrCodeEncryptionFailed:       prefix + cryptoError + "0003",
	ErrCodeDecryptionFailed:       prefix + cryptoError + "0004",
}

// StatusCode returns the HTTP status code associated with the error code
func StatusCode(errorCode string) int {
	if status, exists := HTTPStatusCodeMap[errorCode]; exists {
		return status
	}
	return http.StatusInternalServerError // Default status
}
