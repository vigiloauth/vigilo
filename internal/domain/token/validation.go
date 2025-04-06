package domain

import (
	"fmt"
	"regexp"

	"github.com/vigiloauth/vigilo/internal/errors"
)

func (t *TokenRequest) ValidateCodeVerifier() error {
	codeVerifierLength := len(t.CodeVerifier)
	if codeVerifierLength < 43 || codeVerifierLength > 128 {
		return errors.New(errors.ErrCodeInvalidRequest, fmt.Sprintf("invalid code verifier length (%d): must be between 43 and 128 characters", codeVerifierLength))
	}

	validCodeVerifierRegex := regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	if !validCodeVerifierRegex.MatchString(t.CodeVerifier) {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid characters: only A-Z, a-z, 0-9, '-', and '_' are allowed (Base64 URL encoding)")
	}

	return nil
}
