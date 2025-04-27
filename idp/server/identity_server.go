package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/container"
	"github.com/vigiloauth/vigilo/internal/routes"
)

// VigiloIdentityServer represents the identity library's functionality.
type VigiloIdentityServer struct {
	serverConfig *config.ServerConfig
	container    *container.DIContainer
	appRouter    *routes.AppRouter
}

// NewVigiloIdentityServer creates and initializes a new instance of the IdentityServer.
func NewVigiloIdentityServer() *VigiloIdentityServer {
	module := "Vigilo Identity Server"
	serverConfig := config.GetServerConfig()

	logger := serverConfig.Logger()
	logger.Info(module, "", "Initializing Vigilo Identity Server")

	container := container.NewDIContainer(logger).Init()
	appRouter := routes.NewAppRouter(
		chi.NewRouter(), logger,
		config.GetServerConfig().ForceHTTPS(),
		container.ServerConfigRegistry().Middleware(),
		container.HandlerRegistry(),
	)

	return &VigiloIdentityServer{
		container:    container,
		serverConfig: serverConfig,
		appRouter:    appRouter,
	}
}

func (s *VigiloIdentityServer) Router() chi.Router {
	return s.appRouter.Router()
}

func (s *VigiloIdentityServer) Shutdown() {
	s.container.Shutdown()
}
