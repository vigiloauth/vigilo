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
	scheduler *background.Scheduler
	exitCh    chan struct{}
	logger    *config.Logger
	module    string
}

func NewSchedulerRegistry(services *ServiceRegistry, logger *config.Logger, exitCh chan struct{}) *SchedulerRegistry {
	module := "Scheduler Registry"
	logger.Info(module, "", "Initializing schedulers")

	sr := &SchedulerRegistry{
		services:  services,
		logger:    logger,
		module:    module,
		exitCh:    exitCh,
		scheduler: background.NewScheduler(),
	}

	return sr
}

func (sr *SchedulerRegistry) Start() {
	sr.initJobs()
}

func (sr *SchedulerRegistry) initJobs() {
	sr.registerSMTPJobs()
	sr.registerTokenJobs()
	sr.registerUserJobs()
	sr.registerAuditLogJobs()

	ctx, cancel := context.WithCancel(context.Background())
	go sr.scheduler.StartJobs(ctx)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigCh)

		select {
		case <-sigCh:
			sr.logger.Info(sr.module, "", "Received termination signal")
			cancel()
			close(sr.exitCh)
		case <-sr.exitCh:
			cancel()
		}
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
	tokenJobs := background.NewTokenJobs(c.services.TokenManager(), tokenDeletionInterval)
	c.scheduler.RegisterJob("Expired Token Deletion", tokenJobs.DeleteExpiredTokens)
}

func (c *SchedulerRegistry) registerUserJobs() {
	const userDeletionInterval time.Duration = 24 * time.Hour
	userJobs := background.NewUserJobs(c.services.UserManager(), userDeletionInterval)
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
	if sr.scheduler != nil {
		sr.scheduler.Stop()
		sr.scheduler.Wait()
	}
	close(sr.exitCh)
}
