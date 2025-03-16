package errors

import "fmt"

type ClientError struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
	Field     string `json:"field,omitempty"`
}

func (e *ClientError) Error() string {
	return e.Message
}

func NewClientError(errorCode, message, field string) *ClientError {
	clientError := &ClientError{
		ErrorCode: errorCode,
		Message:   message,
	}

	if field != "" {
		clientError.Field = field
	}

	return clientError
}

func NewDuplicateClientError() error {
	return NewClientError(
		ErrCodeDuplicateClient,
		"A client with the provided ID already exists",
		"client_id",
	)
}

func NewClientNotFoundError() error {
	return NewClientError(
		ErrCodeClientNotFound,
		"Client not found with the provided ID",
		"client_id",
	)
}

func NewInvalidGrantTypeError(invalidGrant string) error {
	return NewClientError(
		ErrCodeInvalidGrantType,
		fmt.Sprintf("Grant type `%s` is not support for public clients", invalidGrant),
		"",
	)
}

func NewInvalidClientTypeError() error {
	return NewClientError(
		ErrCodeInvalidClientType,
		"Client type must be 'public' or 'confidential'",
		"",
	)
}

func NewInvalidRedirectURIError(message string) error {
	return NewClientError(ErrCodeInvalidRedirectURI, message, "")
}

func NewInvalidScopeError(scope string) error {
	return NewClientError(
		ErrCodeInvalidScope,
		fmt.Sprintf("Scope `%s` is not supported", scope),
		"",
	)
}

func NewInvalidGrantCombinationError(grantType string) error {
	return NewClientError(
		ErrCodeInvalidGrantType,
		fmt.Sprintf("`%s` requires another grant type", grantType),
		"",
	)
}

func NewClientSecretError() error {
	return NewClientError(
		ErrCodeClientSecretNotAllowed,
		"Client secret must not be provided for public client registration",
		"",
	)
}
