package domain

import (
	"context"
	"time"

	domain "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

type TokenIssuer interface {
	IssueAccessToken(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error)
	IssueTokenPair(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string, claims *domain.ClaimsRequest) (string, string, error)
	IssueIDToken(ctx context.Context, subject string, audience string, scopes types.Scope, nonce string, acrValues string, authTime time.Time) (string, error)
}
