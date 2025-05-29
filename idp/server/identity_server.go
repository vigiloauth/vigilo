package server

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/container"
	"github.com/vigiloauth/vigilo/v2/internal/routes"
)

// VigiloIdentityServer represents the main identity server structure for the Vigilo application.
// It encapsulates the server configuration, dependency injection container, HTTP server, router,
// logger, and module information.
//
// Fields:
// - serverConfig *config.ServerConfig: Configuration settings for the server.
// - container *container.DIContainer: Dependency injection container for managing application dependencies.
// - httpServer *http.Server: The HTTP server instance used to handle incoming requests.
// - router chi.Router: The router instance for defining and managing HTTP routes.
// - logger *config.Logger: Logger instance for logging server activities and errors.
// - module string: The name of the module associated with this server.
type VigiloIdentityServer struct {
	serverConfig *config.ServerConfig
	container    *container.DIContainer
	httpServer   *http.Server
	router       chi.Router
	logger       *config.Logger
	module       string
}

// NewVigiloIdentityServer initializes and returns a new instance of VigiloIdentityServer.
// It sets up the necessary components including the dependency injection container,
// server configuration, logger, and application router.
//
// The function performs the following steps:
// 1. Retrieves the server configuration and logger.
// 2. Logs the initialization of the Vigilo Identity Provider module.
// 3. Creates and initializes a dependency injection container.
// 4. Configures the application router with middleware, handlers, and settings.
// 5. Returns a fully initialized VigiloIdentityServer instance.
//
// Returns:
//   - *VigiloIdentityServer - A pointer to the initialized VigiloIdentityServer instance.
func NewVigiloIdentityServer() *VigiloIdentityServer {
	module := "Vigilo Identity Provider"
	serverConfig := config.GetServerConfig()

	logger := serverConfig.Logger()
	logger.Info(module, "", "Initializing Vigilo Identity Provider")

	container := container.NewDIContainer(logger)
	container.Init()

	appRouter := routes.NewRouterConfig(
		chi.NewRouter(),
		logger,
		config.GetServerConfig().ForceHTTPS(),
		config.GetServerConfig().EnableRequestLogging(),
		container.ServiceRegistry().Middleware(),
		container.HandlerRegistry(),
	)
	appRouter.Init()

	return &VigiloIdentityServer{
		container:    container,
		serverConfig: serverConfig,
		logger:       logger,
		module:       module,
		httpServer:   container.HTTPServer(),
		router:       appRouter.Router(),
	}
}

// StartServer initializes and starts the Vigilo Identity Server.
// It sets up the HTTP server with the provided router and handles graceful shutdown.
//
// Parameters:
//   - r *chi.Mux: The router to be used for handling HTTP routes.
//
// Behavior:
//   - Configures the "/identity" route and mounts the server's router.
//   - Starts the HTTP server, either with HTTPS (if configured) or plain HTTP.
//   - Logs server startup information, including port and base URL.
//   - Monitors for termination signals (os.Interrupt, syscall.SIGTERM) to gracefully shut down.
//
// Notes:
//   - If HTTPS is enabled, the server requires valid certificate and key file paths.
//   - Exits the application if HTTPS is requested but the certificate or key file paths are missing.
//   - Logs any server errors and exits if the server fails to start.
func (s *VigiloIdentityServer) StartServer(r *chi.Mux) {
	r.Route("/identity", func(subRouter chi.Router) {
		subRouter.Mount("/", s.router)
	})

	s.httpServer.Handler = r

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		s.logger.Info(s.module, "", "Starting VigiloAuth Identity Provider on port [%s] with base URL [%s]",
			s.serverConfig.Port(),
			s.serverConfig.BaseURL(),
		)

		var err error
		if s.serverConfig.ForceHTTPS() {
			certFile := s.serverConfig.CertFilePath()
			keyFile := s.serverConfig.KeyFilePath()

			if certFile == "" || keyFile == "" {
				s.logger.Error(s.module, "", "HTTPS requested but certificate or key file path is not configured. Exiting.")
				os.Exit(1)
			}

			err = s.httpServer.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			s.logger.Error(s.module, "", "HTTP server error: %v", err)
			os.Exit(1)
		}
	}()

	<-stop
}

// Shutdown gracefully shuts down the VigiloIdentityServer instance.
// It performs the following actions:
// 1. Creates a context with a timeout of 10 seconds to ensure the shutdown process does not hang indefinitely.
// 2. Shuts down the container associated with the server.
// 3. Attempts to gracefully shut down the HTTP server using the created context.
//   - If an error occurs during the HTTP server shutdown, it logs the error.
//   - If the shutdown is successful, it logs a message indicating the server was shut down gracefully.
func (s *VigiloIdentityServer) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), constants.TenSecondTimeout)
	defer cancel()

	s.container.Shutdown()

	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.logger.Error(s.module, "", "HTTP serve shutdown err: %v", err)
	} else {
		s.logger.Info(s.module, "", "HTTP server shutdown gracefully")
	}
}

func (s *VigiloIdentityServer) Router() chi.Router {
	return s.router
}
