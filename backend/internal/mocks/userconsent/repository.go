package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ domain.UserConsentRepository = (*MockUserConsentRepository)(nil)

type MockUserConsentRepository struct {
	HasConsentFunc    func(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error)
	SaveConsentFunc   func(ctx context.Context, userID, clientID string, scope types.Scope) error
	RevokeConsentFunc func(ctx context.Context, userID, clientID string) error
}

func (m *MockUserConsentRepository) HasConsent(ctx context.Context, userID, clientID string, scope types.Scope) (bool, error) {
	return m.HasConsentFunc(ctx, userID, clientID, scope)
}

func (m *MockUserConsentRepository) SaveConsent(ctx context.Context, userID, clientID string, scope types.Scope) error {
	return m.SaveConsentFunc(ctx, userID, clientID, scope)
}

func (m *MockUserConsentRepository) RevokeConsent(ctx context.Context, userID, clientID string) error {
	return m.RevokeConsentFunc(ctx, userID, clientID)
}
