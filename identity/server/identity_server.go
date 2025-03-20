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

const (
	contentTypeJSON string = "application/json"
	contentTypeForm string = "application/x-www-form-urlencoded"
)

// VigiloIdentityServer represents the identity library's functionality.
type VigiloIdentityServer struct {
	router        chi.Router
	userHandler   *handlers.UserHandler
	clientHandler *handlers.ClientHandler
	authHandler   *handlers.AuthHandler
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
		authHandler:   container.authHandler,
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

// setupRoutes configures the HTTP routes for the VigiloIdentityServer.
// It applies middleware, sets up user-related endpoints, and groups authenticated routes.
func (s *VigiloIdentityServer) setupRoutes() {
	s.router.Use(s.middleware.RateLimit)

	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.RequiresContentType(contentTypeJSON))

		// User related routes
		r.Post(utils.UserEndpoints.Registration, s.userHandler.Register)
		r.Post(utils.UserEndpoints.Login, s.userHandler.Login)
		r.Post(utils.UserEndpoints.RequestPasswordReset, s.userHandler.RequestPasswordResetEmail)
		r.Patch(utils.UserEndpoints.ResetPassword, s.userHandler.ResetPassword)

		// Client related routes
		r.Post(utils.ClientEndpoints.Registration, s.clientHandler.RegisterClient)
	})

	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.RequiresContentType(contentTypeForm))
		r.Post(utils.AuthEndpoints.GenerateToken, s.authHandler.IssueClientCredentialsToken)
	})

	s.router.Post(utils.ClientEndpoints.RegenerateSecret, s.clientHandler.RegenerateSecret)

	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.AuthMiddleware())
		r.Post(utils.UserEndpoints.Logout, s.userHandler.Logout)
	})
}
