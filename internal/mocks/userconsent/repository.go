package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/internal/domain/userconsent"
)

var _ domain.UserConsentRepository = (*MockUserConsentRepository)(nil)

type MockUserConsentRepository struct {
	HasConsentFunc    func(ctx context.Context, userID, clientID, scope string) (bool, error)
	SaveConsentFunc   func(ctx context.Context, userID, clientID, scope string) error
	RevokeConsentFunc func(ctx context.Context, userID, clientID string) error
}

func (m *MockUserConsentRepository) HasConsent(ctx context.Context, userID, clientID, scope string) (bool, error) {
	return m.HasConsentFunc(ctx, userID, clientID, scope)
}

func (m *MockUserConsentRepository) SaveConsent(ctx context.Context, userID, clientID, scope string) error {
	return m.SaveConsentFunc(ctx, userID, clientID, scope)
}

func (m *MockUserConsentRepository) RevokeConsent(ctx context.Context, userID, clientID string) error {
	return m.RevokeConsentFunc(ctx, userID, clientID)
}
