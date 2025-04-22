package background

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	domain "github.com/vigiloauth/vigilo/internal/domain/token"
)

type TokenJobs struct {
	tokenService domain.TokenService
	interval     time.Duration
	logger       *config.Logger
	module       string
}

func NewTokenJobs(tokenService domain.TokenService, interval time.Duration) *TokenJobs {
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
			t.tokenService.DeleteExpiredTokens(ctx)
		case <-ctx.Done():
			t.logger.Info(t.module, "", "[DeleteExpiredTokens]: Stopping process of deleting expired tokens")
			return
		}
	}
}
