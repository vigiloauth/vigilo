package background

import (
	"context"
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/email"
)

const maxRetries int = 5

type SMTPJobs struct {
	healthCheckTickerInterval time.Duration
	queueTickerInterval       time.Duration
	emailService              domain.EmailService
	logger                    *config.Logger
	module                    string
}

func NewSMTPJobs(
	emailService domain.EmailService,
	healthCheckTicker time.Duration,
	queueTicker time.Duration,
) *SMTPJobs {
	return &SMTPJobs{
		healthCheckTickerInterval: healthCheckTicker,
		queueTickerInterval:       queueTicker,
		emailService:              emailService,
		logger:                    config.GetServerConfig().Logger(),
		module:                    "SMTP Jobs",
	}
}

func (s *SMTPJobs) RunHealthCheck(ctx context.Context) {
	s.logger.Info(s.module, "", "[RunHealthCheck]: Starting SMTP health check")
	ticker := time.NewTicker(s.healthCheckTickerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.emailService.TestConnection(); err != nil {
				s.logger.Error(s.module, "", "[RunHealthCheck]: Failed to test SMTP connection: %v", err)

				continue
			}

		case <-ctx.Done():
			s.logger.Info(s.module, "", "[RunHealthCheck]: Stopping SMTP health check")

			return
		}
	}
}

func (s *SMTPJobs) RunRetryQueueProcessor(ctx context.Context) {
	s.logger.Info(s.module, "", "[RunRetryQueueProcessor]: Starting retry queue processor")
	ticker := time.NewTicker(s.queueTickerInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.processRetryQueue(ctx)
		case <-ctx.Done():
			s.logger.Info(s.module, "", "[RunRetryQueueProcessor]: Stopping retry queue processor")
			return
		}
	}
}

func (s *SMTPJobs) processRetryQueue(ctx context.Context) {
	s.logger.Info(s.module, "", "Processing email retry queue")

	retryQueue := s.emailService.GetEmailRetryQueue()
	if retryQueue.IsEmpty() {
		s.logger.Debug(s.module, "", "Retry queue is empty, skipping")
		return
	}

	var waitGroup sync.WaitGroup
	workerChan := make(chan *domain.EmailRequest)

	numEmails := retryQueue.Size()
	for i := range numEmails {
		waitGroup.Add(1)
		go s.retryWorker(retryQueue, i+1, ctx, workerChan, &waitGroup)
	}

	go func() {
		defer close(workerChan)
		for !retryQueue.IsEmpty() {
			select {
			case <-ctx.Done():
				return
			default:
				request := retryQueue.Remove()
				if request != nil {
					workerChan <- request
				}
			}
		}
	}()

	waitGroup.Wait()
	s.logger.Info(s.module, "", "Retry queue process finished")
}

func (h *SMTPJobs) retryWorker(retryQueue *domain.EmailRetryQueue, workerID int, ctx context.Context, requests <-chan *domain.EmailRequest, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()
	for request := range requests {
		select {
		case <-ctx.Done():
			return
		default:
			if request.Retries >= maxRetries {
				h.logger.Error(h.module, "", "[Worker=%d] Max retries reached for email %s. Dropping.", workerID, request.ID)

				continue
			}

			if err := h.emailService.SendEmail(ctx, request); err != nil {
				request.Retries++
				retryQueue.Add(request)
				h.logger.Error(h.module, "", "[Worker=%d] Failed to retry sending email %s. Retrying. Error: %v", workerID, request.ID, err)
			} else {
				h.logger.Debug(h.module, "", "[Worker=%d] Successfully retried sending email %s.", workerID, request.ID)
			}
		}
	}
}
