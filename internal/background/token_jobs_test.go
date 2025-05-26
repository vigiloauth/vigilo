package background

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/token"
)

func TestTokenJobs_DeleteExpiredTokens(t *testing.T) {
	var mu sync.Mutex
	deleteCalls := 0

	tokenService := &mocks.MockTokenManager{
		DeleteExpiredTokensFunc: func(ctx context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			deleteCalls++
			return nil
		},
	}

	interval := 50 * time.Millisecond
	jobs := NewTokenJobs(tokenService, interval)
	ctx, cancel := context.WithTimeout(context.TODO(), 500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		jobs.DeleteExpiredTokens(ctx)
	}()
	<-ctx.Done()
	wg.Wait()

	assert.GreaterOrEqual(t, deleteCalls, 1, "Should have called DeleteExpiredTokens at least once")
}
