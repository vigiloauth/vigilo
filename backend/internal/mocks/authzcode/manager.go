package mocks

import (
	"context"

	authzCode "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
)

var _ authzCode.AuthorizationCodeManager = (*MockAuthorizationCodeManager)(nil)

type MockAuthorizationCodeManager struct {
	RevokeAuthorizationCodeFunc func(ctx context.Context, code string) error
	GetAuthorizationCodeFunc    func(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error)
	UpdateAuthorizationCodeFunc func(ctx context.Context, authData *authzCode.AuthorizationCodeData) error
}

func (m *MockAuthorizationCodeManager) RevokeAuthorizationCode(ctx context.Context, code string) error {
	return m.RevokeAuthorizationCodeFunc(ctx, code)
}

func (m *MockAuthorizationCodeManager) GetAuthorizationCode(ctx context.Context, code string) (*authzCode.AuthorizationCodeData, error) {
	return m.GetAuthorizationCodeFunc(ctx, code)
}

func (m *MockAuthorizationCodeManager) UpdateAuthorizationCode(ctx context.Context, authData *authzCode.AuthorizationCodeData) error {
	return m.UpdateAuthorizationCodeFunc(ctx, authData)
}
