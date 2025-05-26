package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

var _ domain.UserVerifier = (*MockUserVerifier)(nil)

type MockUserVerifier struct {
	VerifyEmailAddressFunc func(ctx context.Context, verificationCode string) error
}

func (m *MockUserVerifier) VerifyEmailAddress(ctx context.Context, verificationCode string) error {
	return m.VerifyEmailAddressFunc(ctx, verificationCode)
}
