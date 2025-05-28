package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/container"
	"github.com/vigiloauth/vigilo/v2/internal/routes"
)

// VigiloIdentityServer represents the identity library's functionality.
type VigiloIdentityServer struct {
	serverConfig *config.ServerConfig
	container    *container.DIContainer
	routerConfig *routes.RouterConfig
}

// NewVigiloIdentityServer creates and initializes a new instance of the IdentityServer.
func NewVigiloIdentityServer() *VigiloIdentityServer {
	module := "Vigilo Identity Provider"
	serverConfig := config.GetServerConfig()

	logger := serverConfig.Logger()
	logger.Info(module, "", "Initializing Vigilo Identity Provider")

	container := container.NewDIContainer(logger).Init()
	appRouter := routes.NewRouterConfig(
		chi.NewRouter(), logger,
		config.GetServerConfig().ForceHTTPS(),
		config.GetServerConfig().EnableRequestLogging(),
		container.ServiceRegistry().Middleware(),
		container.HandlerRegistry(),
	).Init()

	return &VigiloIdentityServer{
		container:    container,
		serverConfig: serverConfig,
		routerConfig: appRouter,
	}
}

func (s *VigiloIdentityServer) Router() chi.Router {
	return s.routerConfig.Router()
}

func (s *VigiloIdentityServer) HTTPServer() *http.Server {
	return s.container.HTTPServer()
}

func (s *VigiloIdentityServer) Shutdown() {
	s.container.Shutdown()
}
