package server

import (
	"crypto/tls"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/middleware"
	"github.com/vigiloauth/vigilo/internal/web"
)

const (
	contentTypeJSON string = "application/json"
	contentTypeForm string = "application/x-www-form-urlencoded"
)

// VigiloIdentityServer represents the identity library's functionality.
type VigiloIdentityServer struct {
	router chi.Router

	userHandler   *handlers.UserHandler
	clientHandler *handlers.ClientHandler
	authHandler   *handlers.AuthenticationHandler
	authzHandler  *handlers.AuthorizationHandler
	oauthHandler  *handlers.OAuthHandler

	serverConfig *config.ServerConfig
	tlsConfig    *tls.Config
	httpServer   *http.Server
	middleware   *middleware.Middleware
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
		authzHandler:  container.authzHandler,
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
	// Apply Global Middleware
	s.router.Use(s.middleware.RateLimit)

	// Public Routes (No Auth Required)
	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.RequiresContentType(contentTypeJSON))

		// OAuth Authorization & Consent
		r.Get(web.OAuthEndpoints.Authorize, s.authzHandler.AuthorizeClient)
		r.HandleFunc(web.OAuthEndpoints.Login, s.oauthHandler.OAuthLogin)
		r.HandleFunc(web.OAuthEndpoints.Consent, s.oauthHandler.UserConsent)

		// User Registration & Authentication
		r.Post(web.UserEndpoints.Registration, s.userHandler.Register)
		r.Post(web.UserEndpoints.Login, s.userHandler.Login)
		r.Post(web.UserEndpoints.RequestPasswordReset, s.userHandler.RequestPasswordResetEmail)
		r.Patch(web.UserEndpoints.ResetPassword, s.userHandler.ResetPassword)

		// Client Registration
		r.Post(web.ClientEndpoints.Registration, s.clientHandler.RegisterClient)
	})

	// OAuth Token Exchange (Form Data Required)
	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.RequiresContentType(contentTypeForm))
		r.Post(web.OAuthEndpoints.GenerateToken, s.authHandler.IssueClientCredentialsToken)
	})

	// Protected Routes (Auth Required)
	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.AuthMiddleware())

		// User Logout
		r.Post(web.UserEndpoints.Logout, s.userHandler.Logout)

		// Client Secret Management (Stricter Rate Limit)
		r.Group(func(sr chi.Router) {
			sr.Use(s.middleware.StrictRateLimit)
			sr.Post(web.ClientEndpoints.RegenerateSecret, s.clientHandler.RegenerateSecret)
		})
	})
}
