package background

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	mocks "github.com/vigiloauth/vigilo/v2/internal/mocks/user"
)

func TestUserJobs_DeleteUnverifiedUsers(t *testing.T) {
	var mu sync.Mutex
	deleteCalls := 0

	userService := &mocks.MockUserService{
		DeleteUnverifiedUsersFunc: func(ctx context.Context) error {
			mu.Lock()
			defer mu.Unlock()
			deleteCalls++
			return nil
		},
	}

	interval := 50 * time.Millisecond
	jobs := NewUserJobs(userService, interval)
	ctx, cancel := context.WithTimeout(context.TODO(), 500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		jobs.DeleteUnverifiedUsers(ctx)
	}()
	<-ctx.Done()
	wg.Wait()

	assert.GreaterOrEqual(t, deleteCalls, 1, "Should have called DeleteUnverifiedUsers at least once")
}
