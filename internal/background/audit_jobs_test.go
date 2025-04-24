package background

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	mocks "github.com/vigiloauth/vigilo/internal/mocks/audit"
)

func TestAuditJobs_PurgeEvents(t *testing.T) {
	var mu sync.Mutex
	deleteCalls := 0

	auditLogger := &mocks.MockAuditLogger{
		DeleteOldEventsFunc: func(cts context.Context, olderThan time.Time) error {
			mu.Lock()
			defer mu.Unlock()
			deleteCalls++
			return nil
		},
	}

	interval := 50 * time.Millisecond
	jobs := NewAuditJobs(auditLogger, interval, interval)
	ctx, cancel := context.WithTimeout(context.TODO(), 500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		jobs.PurgeLogs(ctx)
	}()
	<-ctx.Done()
	wg.Wait()

	assert.GreaterOrEqual(t, deleteCalls, 1, "Should have called DeleteOldEvents at least once")
}
