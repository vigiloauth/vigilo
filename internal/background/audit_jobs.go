package background

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/audit"
)

type AuditJobs struct {
	auditLogger     domain.AuditLogger
	retentionPeriod time.Duration
	purgeInterval   time.Duration
	logger          *config.Logger
	module          string
}

func NewAuditJobs(auditLogger domain.AuditLogger, retentionPeriod, purgeInterval time.Duration) *AuditJobs {
	return &AuditJobs{
		auditLogger:     auditLogger,
		retentionPeriod: retentionPeriod,
		purgeInterval:   purgeInterval,
		logger:          config.GetServerConfig().Logger(),
		module:          "Audit Jobs",
	}
}

func (a *AuditJobs) PurgeLogs(ctx context.Context) {
	a.logger.Info(a.module, "", "[PurgeLogs]: Starting process of removing old audit logs")
	ticker := time.NewTicker(a.purgeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-a.retentionPeriod)
			if err := a.auditLogger.DeleteOldEvents(ctx, cutoff); err != nil {
				a.logger.Error(a.module, "", "[PurgeLogs]: There was an error deleting old audit logs: %v", err)
				continue //nolint
			}
		case <-ctx.Done():
			a.logger.Info(a.module, "", "[PurgeLogs]: Stopping the process of deleting old audit logs")
			return
		}
	}
}
