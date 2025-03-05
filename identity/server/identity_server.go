package server

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/auth"
	"github.com/vigiloauth/vigilo/internal/middleware"
	"github.com/vigiloauth/vigilo/internal/users"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// VigiloIdentityServer represents the identity library's functionality.
type VigiloIdentityServer struct {
	router       chi.Router
	userHandler  *handlers.UserHandler
	serverConfig *config.ServerConfig
	tlsConfig    *tls.Config
	httpServer   *http.Server
	middleware   *middleware.Middleware
}

// NewVigiloIdentityServer creates and initializes a new instance of IdentityServer.
func NewVigiloIdentityServer(serverConfig *config.ServerConfig) *VigiloIdentityServer {
	if serverConfig == nil {
		serverConfig = config.NewServerConfig()
	}

	userHandler := initializeUserHandler(serverConfig)
	tlsConfig := initializeTLSConfig()
	httpServer := initializeHTTPServer(serverConfig, tlsConfig)

	server := &VigiloIdentityServer{
		router:       chi.NewRouter(),
		userHandler:  userHandler,
		serverConfig: serverConfig,
		tlsConfig:    tlsConfig,
		httpServer:   httpServer,
		middleware:   middleware.NewMiddleware(serverConfig),
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

	s.router.Post(utils.UserEndpoints.Registration, s.userHandler.Register)
	s.router.Post(utils.UserEndpoints.Login, s.userHandler.Login)

	s.router.Group(func(r chi.Router) {
		r.Use(s.middleware.AuthMiddleware())
		r.Post(utils.UserEndpoints.Logout, s.userHandler.Logout)
	})
}

func initializeUserHandler(serverConfig *config.ServerConfig) *handlers.UserHandler {
	userStore := users.GetInMemoryUserStore()
	loginAttemptStore := auth.NewLoginAttemptStore()
	userRegistration := users.NewUserRegistration(userStore, serverConfig.JWTConfig())
	userLogin := auth.NewUserLogin(userStore, loginAttemptStore, serverConfig)

	return handlers.NewUserHandler(userRegistration, userLogin, serverConfig.JWTConfig())
}

func initializeTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

func initializeHTTPServer(serverConfig *config.ServerConfig, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", serverConfig.Port()),
		ReadTimeout:  serverConfig.ReadTimeout(),
		WriteTimeout: serverConfig.WriteTimeout(),
		TLSConfig:    tlsConfig,
	}
}
