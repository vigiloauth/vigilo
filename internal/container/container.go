package container

import (
	"net/http"
	"os"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
)

// DIContainer represents a dependency injection container that manages
// the registration and lifecycle of various application components.
// It provides registries for services, handlers, repositories, schedulers,
// and server configurations, enabling modular and organized application design.
//
// Fields:
// - serviceRegistry: Manages the registration and retrieval of service components.
// - handlerRegistry: Manages the registration and retrieval of handler components.
// - repoRegistry: Manages the registration and retrieval of repository components.
// - schedulerRegistry: Manages the registration and retrieval of scheduler components.
// - serverConfigRegistry: Manages the registration and retrieval of server configuration components.
// - exitCh: A channel used for signaling application shutdown.
// - logger: A logger instance for logging application events.
// - module: Represents the name or identifier of the current module.
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

// Init initializes the DIContainer by setting up various registries and dependencies.
// It creates and configures the following components:
// - RepositoryRegistry: Manages repositories and is initialized with a logger.
// - ServiceRegistry: Manages services and is initialized with the RepositoryRegistry and a logger.
// - HandlerRegistry: Manages handlers and is initialized with the ServiceRegistry and a logger.
// - ServerConfigRegistry: Manages server configurations and is initialized with the ServiceRegistry.
// - SchedulerRegistry: Manages scheduled tasks and is initialized with the ServiceRegistry, a logger, and an exit channel.
//
// Additionally, it starts the SchedulerRegistry to begin processing scheduled tasks.
func (di *DIContainer) Init() {
	di.repoRegistry = NewRepositoryRegistry(di.logger)
	di.serviceRegistry = NewServiceRegistry(di.repoRegistry, di.logger)
	di.handlerRegistry = NewHandlerRegistry(di.serviceRegistry, di.logger)

	di.serverConfigRegistry = NewServerConfigRegistry(di.serviceRegistry)

	di.exitCh = make(chan struct{})
	di.schedulerRegistry = NewSchedulerRegistry(di.serviceRegistry, di.logger, di.exitCh)
	di.schedulerRegistry.Start()
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
	return di.ServerConfigRegistry().HTTPServer()
}

// Shutdown gracefully shuts down the DIContainer by stopping its scheduler registry.
// It waits for the shutdown process to complete or times out after a predefined duration.
// If the timeout is reached, the application exits forcefully.
// Logs are generated to indicate the progress and outcome of the shutdown process.
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
	case <-time.After(constants.ThirtySecondTimeout):
		di.logger.Warn(di.module, "", "Shutdown timeout reached. Forcing application exit.")
		os.Exit(1)
	}
}
