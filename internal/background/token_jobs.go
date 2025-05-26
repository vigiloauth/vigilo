package background

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/token"
)

type TokenJobs struct {
	tokenService domain.TokenManager
	interval     time.Duration
	logger       *config.Logger
	module       string
}

func NewTokenJobs(tokenService domain.TokenManager, interval time.Duration) *TokenJobs {
	return &TokenJobs{
		tokenService: tokenService,
		interval:     interval,
		logger:       config.GetServerConfig().Logger(),
		module:       "Token Jobs",
	}
}

func (t *TokenJobs) DeleteExpiredTokens(ctx context.Context) {
	t.logger.Info(t.module, "", "[DeleteExpiredTokens]: Starting process of deleting expired tokens")
	ticker := time.NewTicker(t.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := t.tokenService.DeleteExpiredTokens(ctx); err != nil {
				t.logger.Error(t.module, "", "[DeleteExpiredTokens]: An error occurred deleting expired tokens: %v", err)
				continue
			}
		case <-ctx.Done():
			t.logger.Info(t.module, "", "[DeleteExpiredTokens]: Stopping process of deleting expired tokens")
			return
		}
	}
}
