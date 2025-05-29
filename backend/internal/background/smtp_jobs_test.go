package background

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/email"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/email"
)

func TestSMTPJobs_RunHealthCheck(t *testing.T) {
	connectionCalls := 0
	var mu sync.Mutex

	emailService := &mocks.MockEmailService{
		TestConnectionFunc: func() error {
			mu.Lock()
			defer mu.Unlock()
			connectionCalls++
			return nil
		},
	}

	interval := 50 * time.Millisecond
	jobs := NewSMTPJobs(emailService, interval, interval)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		jobs.RunHealthCheck(ctx)
	}()
	<-ctx.Done()
	wg.Wait()

	assert.GreaterOrEqual(t, connectionCalls, 1, "Health check should have called TestConnection at least once")
}

func TestSMTPJobs_RunRetryQueueProcess(t *testing.T) {
	queue := &domain.EmailRetryQueue{}
	queue.Add(createTestEmailRequest("testID_1"))
	queue.Add(createTestEmailRequest("testID_2"))

	var mu sync.Mutex
	sendEmailCalls := 0

	emailService := &mocks.MockEmailService{
		GetEmailRetryQueueFunc: func() *domain.EmailRetryQueue {
			mu.Lock()
			defer mu.Unlock()
			return queue
		},
		SendEmailFunc: func(ctx context.Context, request *domain.EmailRequest) error {
			mu.Lock()
			defer mu.Unlock()
			sendEmailCalls++
			return nil
		},
	}

	interval := 50 * time.Millisecond
	jobs := NewSMTPJobs(emailService, interval, interval)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		jobs.RunRetryQueueProcessor(ctx)
	}()
	<-ctx.Done()
	wg.Wait()

	assert.Equal(t, 2, sendEmailCalls, "Retry processor should have processed both emails")
}

func TestSMTPJobs_ProcessRetryQueue_WithErrors(t *testing.T) {
	retryQueue := &domain.EmailRetryQueue{}
	retryQueue.Add(createTestEmailRequest("testID_1"))

	var mu sync.Mutex
	sendEmailCalls := 0

	emailService := &mocks.MockEmailService{
		GetEmailRetryQueueFunc: func() *domain.EmailRetryQueue {
			mu.Lock()
			defer mu.Unlock()
			return retryQueue
		},
		SendEmailFunc: func(ctx context.Context, request *domain.EmailRequest) error {
			mu.Lock()
			defer mu.Unlock()
			sendEmailCalls++
			return errors.New(errors.ErrCodeEmailDeliveryFailed, "failed to deliver email")
		},
	}

	interval := 50 * time.Millisecond
	jobs := NewSMTPJobs(emailService, interval, interval)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		jobs.RunRetryQueueProcessor(ctx)
	}()
	<-ctx.Done()
	wg.Wait()

	assert.GreaterOrEqual(t, sendEmailCalls, 1, "SendEmail should have been called at least once")
	assert.True(t, retryQueue.IsEmpty(), "Retry queue should be empty after reaching max attempts")
}

func TestSMTPJobs_MaxRetries(t *testing.T) {
	retryQueue := &domain.EmailRetryQueue{}
	request := createTestEmailRequest("testID_1")
	request.Retries = 5
	retryQueue.Add(request)

	var mu sync.Mutex
	sendEmailCalls := 0

	emailService := &mocks.MockEmailService{
		GetEmailRetryQueueFunc: func() *domain.EmailRetryQueue {
			mu.Lock()
			defer mu.Unlock()
			return retryQueue
		},
		SendEmailFunc: func(ctx context.Context, request *domain.EmailRequest) error {
			mu.Lock()
			defer mu.Unlock()
			sendEmailCalls++
			return errors.New(errors.ErrCodeEmailDeliveryFailed, "failed to deliver email")
		},
	}

	interval := 50 * time.Millisecond
	jobs := NewSMTPJobs(emailService, interval, interval)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		jobs.RunRetryQueueProcessor(ctx)
	}()
	<-ctx.Done()
	wg.Wait()

	assert.True(t, retryQueue.IsEmpty(), "Retry queue should be empty after dropping max-retried email")
	assert.Equal(t, 0, sendEmailCalls, "SendEmail should not be called for max-retried email")
}

func createTestEmailRequest(id string) *domain.EmailRequest {
	return &domain.EmailRequest{
		ID:        id,
		Recipient: "test@example.com",
		Retries:   0,
		EmailType: domain.AccountVerification,
	}
}
