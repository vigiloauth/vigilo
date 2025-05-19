package mocks

import (
	"context"
	"time"

	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

var _ token.TokenIssuer = (*MockTokenIssuer)(nil)

type MockTokenIssuer struct {
	IssueTokenPairFunc func(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, claims *claims.ClaimsRequest) (string, string, error)
	IssueIDTokenFunc   func(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, authTime time.Time) (string, error)
}

func (m *MockTokenIssuer) IssueTokenPair(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, claims *claims.ClaimsRequest) (string, string, error) {
	return m.IssueTokenPairFunc(ctx, userID, clientID, scopes, nonce, claims)
}

func (m *MockTokenIssuer) IssueIDToken(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, authTime time.Time) (string, error) {
	return m.IssueIDTokenFunc(ctx, userID, clientID, scopes, nonce, authTime)
}
