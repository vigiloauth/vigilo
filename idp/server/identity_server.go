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
	routerConfig *routes.RouterConfig
}

// NewVigiloIdentityServer creates and initializes a new instance of the IdentityServer.
func NewVigiloIdentityServer() *VigiloIdentityServer {
	module := "Vigilo Identity Server"
	serverConfig := config.GetServerConfig()

	logger := serverConfig.Logger()
	logger.Info(module, "", "Initializing Vigilo Identity Server")

	container := container.NewDIContainer(logger).Init()
	appRouter := routes.NewRouterConfig(
		chi.NewRouter(), logger,
		config.GetServerConfig().ForceHTTPS(),
		config.GetServerConfig().EnableRequestLogging(),
		container.ServerConfigRegistry().Middleware(),
		container.HandlerRegistry(),
	)

	return &VigiloIdentityServer{
		container:    container,
		serverConfig: serverConfig,
		routerConfig: appRouter,
	}
}

func (s *VigiloIdentityServer) Router() chi.Router {
	return s.routerConfig.Router()
}

func (s *VigiloIdentityServer) Shutdown() {
	s.container.Shutdown()
}
