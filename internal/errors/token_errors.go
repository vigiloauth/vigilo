package errors

type TokenErrors struct {
	ErrorCode string `json:"error_code"`
	Message   string `json:"message"`
}

func (t *TokenErrors) Error() string {
	return t.Message
}

func NewBaseTokenError(errorCode, message string) *TokenErrors {
	return &TokenErrors{
		ErrorCode: errorCode,
		Message:   message,
	}
}

func NewTokenNotFoundError() *TokenErrors {
	return NewBaseTokenError(ErrCodeTokenNotFound, "Token not found")
}

func NewExpiredTokenError() *TokenErrors {
	return NewBaseTokenError(ErrCodeExpiredToken, "Token has expired")
}
