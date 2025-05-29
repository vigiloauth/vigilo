package mocks

import (
	"context"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

var _ domain.AuthorizationCodeIssuer = (*MockAuthorizationCodeIssuer)(nil)

type MockAuthorizationCodeIssuer struct {
	IssueAuthorizationCodeFunc func(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error)
}

func (m *MockAuthorizationCodeIssuer) IssueAuthorizationCode(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
	return m.IssueAuthorizationCodeFunc(ctx, req)
}
