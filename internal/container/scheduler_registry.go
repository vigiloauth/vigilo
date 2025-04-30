package container

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/background"
)

type SchedulerRegistry struct {
	services  *ServiceRegistry
	ctx       context.Context
	ctxCancel context.CancelFunc
	scheduler *background.Scheduler
	logger    *config.Logger
	module    string
}

func NewSchedulerRegistry(services *ServiceRegistry, logger *config.Logger, exitCh chan struct{}) *SchedulerRegistry {
	module := "Scheduler Registry"
	logger.Info(module, "", "Initializing schedulers")

	ctx, ctxCancel := context.WithCancel(context.Background())

	sr := &SchedulerRegistry{
		services:  services,
		ctx:       ctx,
		ctxCancel: ctxCancel,
		logger:    logger,
		module:    module,
		scheduler: background.NewScheduler(),
	}

	sr.initJobs(exitCh)
	return sr
}

func (sr *SchedulerRegistry) initJobs(exitCh chan struct{}) {
	sr.registerSMTPJobs()
	sr.registerTokenJobs()
	sr.registerUserJobs()
	sr.registerAuditLogJobs()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go sr.scheduler.StartJobs(sr.ctx)

		select {
		case <-sigCh:
			sr.ctxCancel()
			sr.logger.Info(sr.module, "", "Received termination signal, shutting down...")
		case <-sr.ctx.Done():
		}

		signal.Stop(sigCh)
		sr.scheduler.Wait()
		sr.logger.Info(sr.module, "", "All jobs completed. Signaling application exit.")
		close(exitCh)
	}()
}

func (c *SchedulerRegistry) registerSMTPJobs() {
	const healthCheckInterval time.Duration = 15 * time.Minute
	const queueProcessorInterval time.Duration = 10 * time.Minute

	smtpJobs := background.NewSMTPJobs(c.services.EmailService(), healthCheckInterval, queueProcessorInterval)
	c.scheduler.RegisterJob("SMTP Health Check", smtpJobs.RunHealthCheck)
	c.scheduler.RegisterJob("Email Retry Queue", smtpJobs.RunRetryQueueProcessor)
}

func (c *SchedulerRegistry) registerTokenJobs() {
	const tokenDeletionInterval time.Duration = 5 * time.Minute
	tokenJobs := background.NewTokenJobs(c.services.TokenService(), tokenDeletionInterval)
	c.scheduler.RegisterJob("Expired Token Deletion", tokenJobs.DeleteExpiredTokens)
}

func (c *SchedulerRegistry) registerUserJobs() {
	const userDeletionInterval time.Duration = 24 * time.Hour
	userJobs := background.NewUserJobs(c.services.UserService(), userDeletionInterval)
	c.scheduler.RegisterJob("Unverified User Deletion", userJobs.DeleteUnverifiedUsers)
}

func (c *SchedulerRegistry) registerAuditLogJobs() {
	retentionPeriod := config.GetServerConfig().AuditLogConfig().RetentionPeriod()
	const purgeInterval time.Duration = 24 * time.Hour
	auditLogJobs := background.NewAuditJobs(c.services.AuditLogger(), retentionPeriod, purgeInterval)
	c.scheduler.RegisterJob("Audit Log Deletion", auditLogJobs.PurgeLogs)
}

func (sr *SchedulerRegistry) Shutdown() {
	sr.logger.Info(sr.module, "", "Shutting down schedulers and worker pool")
	if sr.ctx != nil {
		sr.ctxCancel()
	}

	if sr.scheduler != nil {
		sr.scheduler.Wait()
	}
}
