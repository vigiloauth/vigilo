package container

import (
	"net/http"
	"sync"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
)

const thirtySecond time.Duration = 30 * time.Second

type DIContainer struct {
	serviceRegistry      *ServiceRegistry
	handlerRegistry      *HandlerRegistry
	repoRegistry         *RepositoryRegistry
	schedulerRegistry    *SchedulerRegistry
	serverConfigRegistry *ServerConfigRegistry

	exitCh chan struct{}
	logger *config.Logger
	module string
}

func NewDIContainer(logger *config.Logger) *DIContainer {
	module := "DI Container"
	logger.Info(module, "", "Initializing Dependencies")

	return &DIContainer{
		logger: logger,
		module: module,
	}
}

func (di *DIContainer) Init() *DIContainer {
	di.repoRegistry = NewRepositoryRegistry(di.logger)
	di.serviceRegistry = NewServiceRegistry(di.repoRegistry, di.logger)
	di.handlerRegistry = NewHandlerRegistry(di.serviceRegistry, di.logger)

	di.serverConfigRegistry = NewServerConfigRegistry(di.serviceRegistry)

	di.exitCh = make(chan struct{})
	di.schedulerRegistry = NewSchedulerRegistry(di.serviceRegistry, di.logger, di.exitCh)
	di.schedulerRegistry.Start()
	return di
}

func (di *DIContainer) ServiceRegistry() *ServiceRegistry {
	return di.serviceRegistry
}

func (di *DIContainer) HandlerRegistry() *HandlerRegistry {
	return di.handlerRegistry
}

func (di *DIContainer) RepositoryRegistry() *RepositoryRegistry {
	return di.repoRegistry
}

func (di *DIContainer) ServerConfigRegistry() *ServerConfigRegistry {
	return di.serverConfigRegistry
}

func (di *DIContainer) HTTPServer() *http.Server {
	return di.ServerConfigRegistry().httpServer
}

func (di *DIContainer) Shutdown() {
	di.logger.Info(di.module, "", "Shutting down DI Container")

	done := make(chan struct{})
	go func() {
		di.schedulerRegistry.Shutdown()
		close(done)
	}()

	select {
	case <-done:
		di.logger.Info(di.module, "", "DI Container shut down successfully")
	case <-time.After(thirtySecond):
		di.logger.Warn(di.module, "", "Shutdown timeout reached. Forcing application exit.")
	}
}

type LazyInit[T any] struct {
	once     sync.Once
	value    T
	initFunc func() T
}

func (l *LazyInit[T]) Get() T {
	l.once.Do(func() {
		l.value = l.initFunc()
	})

	return l.value
}
