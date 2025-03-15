package errors

import "fmt"

// EmailError is the base error type for all email-related errors
type EmailError struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
}

func (e *EmailError) Error() string {
	return e.Message
}

// NewBaseError creates a new BaseError with a custom message and error code
func NewBaseError(errorCode, message string) *EmailError {
	return &EmailError{
		ErrorCode: errorCode,
		Message:   message,
	}
}

// EmailDeliveryError represents an error when email delivery fails
func NewEmailDeliveryError(err error) *EmailError {
	return NewBaseError(ErrCodeEmailDeliveryFailed, fmt.Sprintf("Email delivery failed, added to retry queue: %v", err))
}

// EmailTemplateParseError represents an error when email template parsing fails
func NewEmailTemplateParseError(err error) *EmailError {
	return NewBaseError(ErrCodeEmailTemplateParseFailed, fmt.Sprintf("Failed to parse email template: %v", err))
}

// TemplateRenderingError represents an error when template rendering fails
func NewTemplateRenderingError(err error) *EmailError {
	return NewBaseError(ErrCodeTemplateRenderingFailed, fmt.Sprintf("Template rendering failed: %v", err))
}

// UnsupportedEncryptionTypeError represents an error when an unsupported encryption type is encountered
func NewUnsupportedEncryptionTypeError(encryption string) *EmailError {
	return NewBaseError(ErrCodeUnsupportedEncryptionType, fmt.Sprintf("Unsupported encryption type: %s", encryption))
}

// SMTPServerConnectionError represents an error when SMTP server connection fails
func NewSMTPServerConnectionError(err error) *EmailError {
	return NewBaseError(ErrCodeSMTPServerConnectionFailed, fmt.Sprintf("SMTP server connection failed: %v", err))
}

// TLSConnectionError represents an error when a TLS connection fails
func NewTLSConnectionError(err error) *EmailError {
	return NewBaseError(ErrCodeTLSConnectionFailed, fmt.Sprintf("TLS connection failed: %v", err))
}

// ClientCreationError represents an error when creating a new client fails
func NewClientCreationError(err error) *EmailError {
	return NewBaseError(ErrCodeClientCreationFailed, fmt.Sprintf("Error creating new client: %v", err))
}

// StartTLSFailedError represents an error when StartTLS fails
func NewStartTLSFailedError(err error) *EmailError {
	return NewBaseError(ErrCodeStartTLSFailed, fmt.Sprintf("StartTLS failed: %v", err))
}

// SMTPAuthenticationError represents an error when SMTP authentication fails
func NewSMTPAuthenticationError(err error) *EmailError {
	return NewBaseError(ErrCodeSMTPAuthenticationFailed, fmt.Sprintf("SMTP authentication failed: %v", err))
}
