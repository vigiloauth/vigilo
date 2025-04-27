package container

import (
	"sync"

	"github.com/vigiloauth/vigilo/idp/config"
)

type DIContainer struct {
	serviceRegistry      *ServiceRegistry
	handlerRegistry      *HandlerRegistry
	repoRegistry         *RepositoryRegistry
	schedulerRegistry    *SchedulerRegistry
	serverConfigRegistry *ServerConfigRegistry

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
	di.schedulerRegistry = NewSchedulerRegistry(di.serviceRegistry, di.logger)
	di.serverConfigRegistry = NewServerConfigRegistry(di.logger, di.serviceRegistry)
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

func (di *DIContainer) SchedulerRegistry() *SchedulerRegistry {
	return di.schedulerRegistry
}

func (di *DIContainer) ServerConfigRegistry() *ServerConfigRegistry {
	return di.serverConfigRegistry
}

func (di *DIContainer) Shutdown() {
	di.logger.Info(di.module, "", "Shutting down DI Container")
	di.schedulerRegistry.Shutdown()
	di.logger.Info(di.module, "", "DI Container shut down successfully")
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
