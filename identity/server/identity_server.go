package server

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/middleware"
	"github.com/vigiloauth/vigilo/internal/web"
)

const (
	contentTypeJSON string = "application/json"
	contentTypeForm string = "application/x-www-form-urlencoded"
)

var clientURLParam string = fmt.Sprintf("/{%s}", common.ClientID)

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

	logger *config.Logger
	module string
}

// NewVigiloIdentityServer creates and initializes a new instance of IdentityServer.
func NewVigiloIdentityServer() *VigiloIdentityServer {
	module := "VigiloIdentityServer"
	logger := config.GetLogger()
	logger.Info(module, "Initializing Vigilo Identity Server")

	container := NewServiceContainer()
	serverConfig := config.GetServerConfig()

	server := &VigiloIdentityServer{
		router:        chi.NewRouter(),
		userHandler:   container.userHandler,
		clientHandler: container.clientHandler,
		authHandler:   container.authHandler,
		authzHandler:  container.authzHandler,
		oauthHandler:  container.oauthHandler,
		serverConfig:  serverConfig,
		tlsConfig:     container.tlsConfig,
		httpServer:    container.httpServer,
		middleware:    container.middleware,
		logger:        logger,
		module:        module,
	}

	server.setupRoutes()
	if serverConfig.ForceHTTPS() {
		server.logger.Info(server.module, "Vigilo Identity Server is running on HTTPS")
		server.router.Use(server.middleware.RedirectToHTTPS)
	} else {
		server.logger.Warn(server.module, "Vigilo Identity Server is running on HTTP. It is recommended to enable HTTPS in production environments")
	}

	return server
}

// Router returns the pre-configured router instance for integration.
func (s *VigiloIdentityServer) Router() chi.Router {
	return s.router
}

func (s *VigiloIdentityServer) setupRoutes() {
	// Apply Global Middleware
	s.router.Use(s.middleware.RateLimit)

	// Public Routes (No Auth Required)
	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.RequiresContentType(contentTypeJSON))

		r.HandleFunc(web.OAuthEndpoints.UserConsent, s.oauthHandler.UserConsent)

		// GET Routes
		r.Group(func(gr chi.Router) {
			gr.Use(s.middleware.RequireRequestMethod(http.MethodGet))
			gr.Get(web.OAuthEndpoints.Authorize, s.authzHandler.AuthorizeClient)
		})

		// POST Routes
		r.Group(func(pr chi.Router) {
			pr.Use(s.middleware.RequireRequestMethod(http.MethodPost))
			pr.Post(web.OAuthEndpoints.TokenExchange, s.authzHandler.TokenExchange)
			pr.Post(web.OAuthEndpoints.Login, s.oauthHandler.OAuthLogin)
			pr.Post(web.UserEndpoints.Registration, s.userHandler.Register)
			pr.Post(web.UserEndpoints.Login, s.userHandler.Login)
			pr.Post(web.UserEndpoints.RequestPasswordReset, s.userHandler.RequestPasswordResetEmail)
			pr.Post(web.ClientEndpoints.Register, s.clientHandler.RegisterClient)
		})

		// PATCH Routes
		r.Group(func(pr chi.Router) {
			pr.Use(s.middleware.RequireRequestMethod(http.MethodPatch))
			pr.Patch(web.UserEndpoints.ResetPassword, s.userHandler.ResetPassword)
		})
	})

	// OAuth Token Exchange (Form Data Required)
	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.RequiresContentType(contentTypeForm))

		r.Group(func(pr chi.Router) {
			pr.Use(s.middleware.RequireRequestMethod(http.MethodPost))
			pr.Post(web.OAuthEndpoints.ClientCredentialsToken, s.authHandler.IssueClientCredentialsToken)
		})
	})

	// Protected Routes (Auth Required)
	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.AuthMiddleware())

		r.Route(web.ClientEndpoints.ClientConfiguration, func(cr chi.Router) {
			cr.Get(clientURLParam, s.clientHandler.ManageClientConfiguration)
			cr.Put(clientURLParam, s.clientHandler.ManageClientConfiguration)
			cr.Delete(clientURLParam, s.clientHandler.ManageClientConfiguration)
		})

		// POST Routes
		r.Group(func(pr chi.Router) {
			pr.Use(s.middleware.RequireRequestMethod(http.MethodPost))
			pr.Post(web.UserEndpoints.Logout, s.userHandler.Logout)

			// Client Secret Management (Stricter Rate Limit)
			r.Group(func(sr chi.Router) {
				sr.Use(s.middleware.StrictRateLimit)
				sr.Post(web.ClientEndpoints.RegenerateSecret+clientURLParam, s.clientHandler.RegenerateSecret)
			})
		})
	})
}
