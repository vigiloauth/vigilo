package server

import (
	"crypto/tls"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/middleware"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// VigiloIdentityServer represents the identity library's functionality.
type VigiloIdentityServer struct {
	router        chi.Router
	userHandler   *handlers.UserHandler
	clientHandler *handlers.ClientHandler
	serverConfig  *config.ServerConfig
	tlsConfig     *tls.Config
	httpServer    *http.Server
	middleware    *middleware.Middleware
}

// NewVigiloIdentityServer creates and initializes a new instance of IdentityServer.
func NewVigiloIdentityServer() *VigiloIdentityServer {
	container := NewServiceContainer()
	serverConfig := config.GetServerConfig()

	server := &VigiloIdentityServer{
		router:        chi.NewRouter(),
		userHandler:   container.userHandler,
		clientHandler: container.clientHandler,
		serverConfig:  serverConfig,
		tlsConfig:     container.tlsConfig,
		httpServer:    container.httpServer,
		middleware:    container.middleware,
	}

	server.setupRoutes()
	if serverConfig.ForceHTTPS() {
		server.router.Use(server.middleware.RedirectToHTTPS)
	}

	return server
}

// Router returns the pre-configured router instance for integration.
func (s *VigiloIdentityServer) Router() chi.Router {
	return s.router
}

func (s *VigiloIdentityServer) setupRoutes() {
	s.router.Use(s.middleware.RateLimit)

	// User related routes
	s.router.Post(utils.UserEndpoints.Registration, s.userHandler.Register)
	s.router.Post(utils.UserEndpoints.Login, s.userHandler.Login)
	s.router.Post(utils.UserEndpoints.RequestPasswordReset, s.userHandler.RequestPasswordResetEmail)
	s.router.Patch(utils.UserEndpoints.ResetPassword, s.userHandler.ResetPassword)

	s.router.Post(utils.ClientEndpoints.Registration, s.clientHandler.Register)

	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.AuthMiddleware())
		r.Post(utils.UserEndpoints.Logout, s.userHandler.Logout)
	})
}
