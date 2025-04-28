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

	// User errors
	ErrCodeDuplicateUser      string = "duplicate_user"
	ErrCodeUserNotFound       string = "user_not_found"
	ErrCodeInvalidCredentials string = "invalid_credentials"
	ErrCodeAccountLocked      string = "account_locked"
	ErrCodeUnauthorized       string = "unauthorized"
	ErrCodeLoginRequired      string = "login_required"
	ErrCodeConsentRequired    string = "consent_required"
	ErrCodeInsufficientRole   string = "insufficient_role"

	// Token errors
	ErrCodeTokenNotFound string = "token_not_found"
	ErrCodeExpiredToken  string = "token_expired"
	ErrCodeTokenCreation string = "token_creation"
	ErrCodeInvalidToken  string = "invalid_token"
	ErrCodeTokenParsing  string = "token_parsing"

	// Email errors
	ErrCodeConnectionFailed    string = "connection_failed"
	ErrCodeEmailDeliveryFailed string = "delivery_failed"

	// Client errors
	ErrCodeInvalidClient          string = "invalid_client"
	ErrCodeInvalidGrant           string = "invalid_grant"
	ErrCodeInvalidRedirectURI     string = "invalid_redirect_uri"
	ErrCodeInsufficientScope      string = "insufficient_scope"
	ErrCodeClientSecretNotAllowed string = "client_secret_not_allowed"
	ErrCodeClientNotFound         string = "client_not_found"
	ErrCodeDuplicateClient        string = "duplicate_client"
	ErrCodeInvalidResponseType    string = "invalid_response_type"
	ErrCodeUnauthorizedClient     string = "unauthorized_client"
	ErrCodeUnsupportedGrantType   string = "unsupported_grant_type"
	ErrCodeAccessDenied           string = "access_denied"
	ErrCodeInvalidClientMetadata  string = "invalid_client_metadata"

	// Session errors
	ErrCodeDuplicateSession string = "duplicate_session"
	ErrCodeSessionNotFound  string = "session_not_found"
	ErrCodeInvalidSession   string = "invalid_session"

	// Middleware Errors
	ErrCodeRequestLimitExceeded = "request_limit_exceeded"

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
)

// HTTP status code mappings
var statusCodeMap = map[string]int{
	// 400 Bad Request
	ErrCodeEmptyInput:             http.StatusBadRequest,
	ErrCodeMissingNumber:          http.StatusBadRequest,
	ErrCodeMissingSymbol:          http.StatusBadRequest,
	ErrCodeMissingUppercase:       http.StatusBadRequest,
	ErrCodeInvalidPasswordFormat:  http.StatusBadRequest,
	ErrCodePasswordLength:         http.StatusBadRequest,
	ErrCodeInvalidEmail:           http.StatusBadRequest,
	ErrCodeValidationError:        http.StatusBadRequest,
	ErrCodeMissingHeader:          http.StatusBadRequest,
	ErrCodeUnauthorizedClient:     http.StatusBadRequest,
	ErrCodeClientSecretNotAllowed: http.StatusBadRequest,
	ErrCodeInvalidResponseType:    http.StatusBadRequest,
	ErrCodeInvalidContentType:     http.StatusBadRequest,
	ErrCodeUnsupportedGrantType:   http.StatusBadRequest,
	ErrCodeInvalidRequest:         http.StatusBadRequest,
	ErrCodeBadRequest:             http.StatusBadRequest,
	ErrCodeInvalidClientMetadata:  http.StatusBadRequest,
	ErrCodeInvalidGrant:           http.StatusBadRequest,
	ErrCodeInvalidInput:           http.StatusBadRequest,
	ErrCodeInvalidDate:            http.StatusBadRequest,

	// 401 Unauthorized
	ErrCodeInvalidCredentials:       http.StatusUnauthorized,
	ErrCodeInvalidClient:            http.StatusUnauthorized,
	ErrCodeUnauthorized:             http.StatusUnauthorized,
	ErrCodeExpiredToken:             http.StatusUnauthorized,
	ErrCodeInvalidToken:             http.StatusUnauthorized,
	ErrCodeTokenParsing:             http.StatusUnauthorized,
	ErrCodeLoginRequired:            http.StatusUnauthorized,
	ErrCodeConsentRequired:          http.StatusUnauthorized,
	ErrCodeInvalidSession:           http.StatusUnauthorized,
	ErrCodeInvalidAuthorizationCode: http.StatusUnauthorized,
	ErrCodeExpiredAuthorizationCode: http.StatusUnauthorized,

	// 404 Not Found
	ErrCodeUserNotFound:              http.StatusNotFound,
	ErrCodeTokenNotFound:             http.StatusNotFound,
	ErrCodeClientNotFound:            http.StatusNotFound,
	ErrCodeSessionNotFound:           http.StatusNotFound,
	ErrCodeResourceNotFound:          http.StatusNotFound,
	ErrCodeAuthorizationCodeNotFound: http.StatusNotFound,

	// 403 Forbidden
	ErrCodeInvalidRedirectURI: http.StatusForbidden,
	ErrCodeAccessDenied:       http.StatusForbidden,
	ErrCodeInsufficientRole:   http.StatusForbidden,
	ErrCodeInsufficientScope:  http.StatusForbidden,

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
	ErrCodeInternalServerError: http.StatusInternalServerError,
	ErrCodeTokenCreation:       http.StatusInternalServerError,
	ErrCodeEmailDeliveryFailed: http.StatusInternalServerError,

	// 502 Bad Gateway
	ErrCodeConnectionFailed: http.StatusBadGateway,

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
