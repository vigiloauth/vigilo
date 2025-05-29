package mocks

import (
	"context"
	"time"

	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
)

var _ authz.AuthorizationCodeRepository = (*MockAuthorizationCodeRepository)(nil)

type MockAuthorizationCodeRepository struct {
	StoreAuthorizationCodeFunc  func(ctx context.Context, code string, data *authz.AuthorizationCodeData, expiresAt time.Time) error
	GetAuthorizationCodeFunc    func(ctx context.Context, code string) (*authz.AuthorizationCodeData, error)
	DeleteAuthorizationCodeFunc func(ctx context.Context, code string) error
	UpdateAuthorizationCodeFunc func(ctx context.Context, code string, authData *authz.AuthorizationCodeData) error
}

func (m *MockAuthorizationCodeRepository) StoreAuthorizationCode(ctx context.Context, code string, data *authz.AuthorizationCodeData, expiresAt time.Time) error {
	return m.StoreAuthorizationCodeFunc(ctx, code, data, expiresAt)
}

func (m *MockAuthorizationCodeRepository) GetAuthorizationCode(ctx context.Context, code string) (*authz.AuthorizationCodeData, error) {
	return m.GetAuthorizationCodeFunc(ctx, code)
}

func (m *MockAuthorizationCodeRepository) DeleteAuthorizationCode(ctx context.Context, code string) error {
	return m.DeleteAuthorizationCodeFunc(ctx, code)
}

func (m *MockAuthorizationCodeRepository) UpdateAuthorizationCode(ctx context.Context, code string, authData *authz.AuthorizationCodeData) error {
	return m.UpdateAuthorizationCodeFunc(ctx, code, authData)
}
