package container

import (
	"runtime"
	"testing"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
)

func TestSchedulerShutdown(t *testing.T) {
	logger := config.GetServerConfig().Logger()
	services := NewServiceRegistry(NewRepositoryRegistry(logger), logger)
	schedulerRegistry := NewSchedulerRegistry(services, logger, make(chan struct{}))

	go func() {
		schedulerRegistry.Shutdown()
	}()

	select {
	case <-schedulerRegistry.exitCh:
		t.Log("Shutdown completed successfully")
	case <-time.After(5 * time.Second):
		t.Fatalf("Shutdown did not complete within the expected time")
	}

	numGoroutines := runtime.NumGoroutine()
	t.Logf("Number of goroutines after shutdown: %d", numGoroutines)
	if numGoroutines > 2 {
		t.Errorf("Leaked goroutines detected: %d", numGoroutines)
	}
}
