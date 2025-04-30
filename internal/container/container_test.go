package container

import (
	"testing"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
)

func TestSchedulerShutdown(t *testing.T) {
	exitCh := make(chan struct{})
	logger := config.GetServerConfig().Logger()
	services := NewServiceRegistry(NewRepositoryRegistry(logger), logger)
	schedulerRegistry := NewSchedulerRegistry(services, logger, exitCh)

	go func() {
		time.Sleep(2 * time.Second)
		schedulerRegistry.Shutdown()
	}()

	<-exitCh // Wait for exit signal
	t.Log("Shutdown completed successfully")
}
