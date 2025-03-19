package server

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/handlers"
	auth "github.com/vigiloauth/vigilo/internal/auth/authentication"
	login "github.com/vigiloauth/vigilo/internal/auth/loginattempt"
	password "github.com/vigiloauth/vigilo/internal/auth/passwordreset"
	registration "github.com/vigiloauth/vigilo/internal/auth/registration"
	session "github.com/vigiloauth/vigilo/internal/auth/session"
	client "github.com/vigiloauth/vigilo/internal/client/service"
	clientStore "github.com/vigiloauth/vigilo/internal/client/store"

	"github.com/vigiloauth/vigilo/internal/email"
	"github.com/vigiloauth/vigilo/internal/middleware"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
)

// ServiceContainer holds all the services and dependencies needed for the server.
type ServiceContainer struct {
	tokenStore        token.TokenStore
	loginAttemptStore login.LoginAttemptStore
	userStore         users.UserStore
	clientStore       clientStore.ClientStore

	passwordResetEmailService email.EmailService
	emailNotificationService  email.EmailService

	tokenManager         token.TokenService
	sessionService       session.Session
	registrationService  registration.Registration
	authService          auth.Authentication
	passwordResetService password.PasswordReset
	clientService        client.ClientService

	userHandler   *handlers.UserHandler
	clientHandler *handlers.ClientHandler

	middleware *middleware.Middleware
	tlsConfig  *tls.Config
	httpServer *http.Server
}

// NewServiceContainer creates a new ServiceContainer instance with all services initialized.
// It initializes in-memory stores, services, handlers, middleware, TLS configuration, and the HTTP server.
//
// Returns:
//
//	*ServiceContainer: A new ServiceContainer instance.
func NewServiceContainer() *ServiceContainer {
	container := &ServiceContainer{}
	container.initializeInMemoryStores()
	container.initializeServices()
	container.initializeHandlers()
	container.initializeServerConfigs()
	return container
}

// initializeInMemoryStores initializes the in-memory data stores used by the service container.
func (c *ServiceContainer) initializeInMemoryStores() {
	c.tokenStore = token.GetInMemoryTokenStore()
	c.userStore = users.GetInMemoryUserStore()
	c.loginAttemptStore = login.NewInMemoryLoginAttemptStore()
	c.clientStore = clientStore.NewInMemoryClientStore()
}

// initializeServices initializes the various services used by the service container.
func (c *ServiceContainer) initializeServices() {
	c.passwordResetEmailService, _ = email.NewPasswordResetEmailService()
	c.emailNotificationService, _ = email.NewEmailNotificationService()
	c.tokenManager = token.NewTokenService(c.tokenStore)
	c.sessionService = session.NewSessionService(c.tokenManager, c.tokenStore)
	c.passwordResetService = password.NewPasswordResetService(c.tokenManager, c.userStore, c.passwordResetEmailService)
	c.registrationService = registration.NewRegistrationService(c.userStore, c.tokenManager)
	c.authService = auth.NewAuthenticationService(c.userStore, c.loginAttemptStore, c.tokenManager)
	c.clientService = client.NewClientService(c.clientStore)
}

// initializeHandlers initializes the HTTP handlers used by the service container.
func (c *ServiceContainer) initializeHandlers() {
	c.userHandler = handlers.NewUserHandler(c.registrationService, c.authService, c.passwordResetService, c.sessionService)
	c.clientHandler = handlers.NewClientHandler(c.clientService)
}

// initializeServerConfigs initializes the server-related configurations,
// including middleware, TLS configuration, and the HTTP server.
func (c *ServiceContainer) initializeServerConfigs() {
	c.middleware = middleware.NewMiddleware(c.tokenManager, c.tokenManager)
	c.tlsConfig = initializeTLSConfig()
	c.httpServer = initializeHTTPServer(c.tlsConfig)
}

// initializeTLSConfig creates and returns a TLS configuration.
// It sets the minimum TLS version and preferred cipher suites.
//
// Returns:
//
//	*tls.Config: A TLS configuration instance.
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

// initializeHTTPServer creates and returns an HTTP server instance.
// It configures the server address, read timeout, write timeout, and TLS configuration.
//
// Parameters:
//
//	tlsConfig *tls.Config: The TLS configuration to use.
//
// Returns:
//
//	*http.Server: An HTTP server instance.
func initializeHTTPServer(tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", config.GetServerConfig().Port()),
		ReadTimeout:  config.GetServerConfig().ReadTimeout(),
		WriteTimeout: config.GetServerConfig().WriteTimeout(),
		TLSConfig:    tlsConfig,
	}
}
