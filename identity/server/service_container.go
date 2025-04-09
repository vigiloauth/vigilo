package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/handlers"
	auth "github.com/vigiloauth/vigilo/internal/domain/authentication"
	authzCode "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	cookie "github.com/vigiloauth/vigilo/internal/domain/cookies"
	email "github.com/vigiloauth/vigilo/internal/domain/email"
	login "github.com/vigiloauth/vigilo/internal/domain/login"
	password "github.com/vigiloauth/vigilo/internal/domain/passwordreset"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	userConsent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/middleware"

	authzCodeRepo "github.com/vigiloauth/vigilo/internal/repository/authzcode"
	clientRepo "github.com/vigiloauth/vigilo/internal/repository/client"
	loginRepo "github.com/vigiloauth/vigilo/internal/repository/login"
	sessionRepo "github.com/vigiloauth/vigilo/internal/repository/session"
	tokenRepo "github.com/vigiloauth/vigilo/internal/repository/token"
	userRepo "github.com/vigiloauth/vigilo/internal/repository/user"
	consentRepo "github.com/vigiloauth/vigilo/internal/repository/userconsent"

	authz "github.com/vigiloauth/vigilo/internal/domain/authorization"
	authService "github.com/vigiloauth/vigilo/internal/service/authentication"
	authzService "github.com/vigiloauth/vigilo/internal/service/authorization"
	authzCodeService "github.com/vigiloauth/vigilo/internal/service/authzcode"
	clientService "github.com/vigiloauth/vigilo/internal/service/client"
	cookieService "github.com/vigiloauth/vigilo/internal/service/cookies"
	emailService "github.com/vigiloauth/vigilo/internal/service/email"
	loginService "github.com/vigiloauth/vigilo/internal/service/login"
	passwordService "github.com/vigiloauth/vigilo/internal/service/passwordreset"
	sessionService "github.com/vigiloauth/vigilo/internal/service/session"
	tokenService "github.com/vigiloauth/vigilo/internal/service/token"
	userService "github.com/vigiloauth/vigilo/internal/service/user"
	consentService "github.com/vigiloauth/vigilo/internal/service/userconsent"
)

// ServiceContainer holds all the services and dependencies needed for the server.
type ServiceContainer struct {
	tokenRepo        token.TokenRepository
	loginAttemptRepo login.LoginAttemptRepository
	userRepo         users.UserRepository
	clientRepo       client.ClientRepository
	consentRepo      userConsent.UserConsentRepository
	authzCodeRepo    authzCode.AuthorizationCodeRepository
	sessionRepo      session.SessionRepository

	// Lazy-loaded services using sync.Once to ensure thread safety
	passwordResetEmailOnce   sync.Once
	emailNotificationOnce    sync.Once
	tokenServiceOnce         sync.Once
	sessionServiceOnce       sync.Once
	userServiceOnce          sync.Once
	passwordResetServiceOnce sync.Once
	clientServiceOnce        sync.Once
	consentServiceOnce       sync.Once
	authzCodeServiceOnce     sync.Once
	loginAttemptServiceOnce  sync.Once
	authorizationServiceOnce sync.Once
	httpCookieServiceOnce    sync.Once
	authServiceOnce          sync.Once

	passwordResetEmailService email.EmailService
	emailNotificationService  email.EmailService
	tokenService              token.TokenService
	sessionService            session.SessionService
	userService               users.UserService
	passwordResetService      password.PasswordResetService
	clientService             client.ClientService
	consentService            userConsent.UserConsentService
	authzCodeService          authzCode.AuthorizationCodeService
	loginAttemptService       login.LoginAttemptService
	authorizationService      authz.AuthorizationService
	httpCookieService         cookie.HTTPCookieService
	authService               auth.AuthenticationService

	passwordResetEmailServiceInit func() email.EmailService
	emailNotificationServiceInit  func() email.EmailService
	tokenServiceInit              func() token.TokenService
	sessionServiceInit            func() session.SessionService
	userServiceInit               func() users.UserService
	passwordResetServiceInit      func() password.PasswordResetService
	clientServiceInit             func() client.ClientService
	consentServiceInit            func() userConsent.UserConsentService
	authzCodeServiceInit          func() authzCode.AuthorizationCodeService
	loginAttemptServiceInit       func() login.LoginAttemptService
	authorizationServiceInit      func() authz.AuthorizationService
	httpCookieServiceInit         func() cookie.HTTPCookieService
	authServiceInit               func() auth.AuthenticationService

	userHandler   *handlers.UserHandler
	clientHandler *handlers.ClientHandler
	tokenHandler  *handlers.TokenHandler
	authzHandler  *handlers.AuthorizationHandler
	oauthHandler  *handlers.OAuthHandler

	middleware *middleware.Middleware
	tlsConfig  *tls.Config
	httpServer *http.Server

	logger *config.Logger
	module string
}

// NewServiceContainer creates a new ServiceContainer instance with all services initialized.
// It initializes in-memory stores, services, handlers, middleware, TLS configuration, and the HTTP server.
//
// Returns:
//
//	*ServiceContainer: A new ServiceContainer instance.
func NewServiceContainer() *ServiceContainer {
	container := &ServiceContainer{
		logger: config.GetLogger(),
		module: "ServiceContainer",
	}
	container.initializeInMemoryRepositories()
	container.initializeServices()
	container.initializeHandlers()
	container.initializeServerConfigs()
	return container
}

// initializeInMemoryRepositories initializes the in-memory data stores used by the service container.
func (c *ServiceContainer) initializeInMemoryRepositories() {
	c.logger.Info(c.module, "Initializing in memory repositories")
	c.tokenRepo = tokenRepo.GetInMemoryTokenRepository()
	c.userRepo = userRepo.GetInMemoryUserRepository()
	c.loginAttemptRepo = loginRepo.GetInMemoryLoginRepository()
	c.clientRepo = clientRepo.GetInMemoryClientRepository()
	c.consentRepo = consentRepo.GetInMemoryUserConsentRepository()
	c.authzCodeRepo = authzCodeRepo.GetInMemoryAuthorizationCodeRepository()
	c.sessionRepo = sessionRepo.GetInMemorySessionRepository()
}

// initializeServices defines getter methods for lazy service initialization**
func (c *ServiceContainer) initializeServices() {
	c.logger.Info(c.module, "Initializing Services")
	c.httpCookieServiceInit = func() cookie.HTTPCookieService {
		c.logger.Debug(c.module, "Initializing HTTPCookieService")
		return cookieService.NewHTTPCookieServiceImpl()
	}
	c.tokenServiceInit = func() token.TokenService {
		c.logger.Debug(c.module, "Initializing TokenService")
		return tokenService.NewTokenServiceImpl(c.tokenRepo)
	}
	c.sessionServiceInit = func() session.SessionService {
		c.logger.Debug(c.module, "Initializing SessionService")
		return sessionService.NewSessionServiceImpl(c.getTokenService(), c.sessionRepo, c.getHTTPSessionCookieService())
	}
	c.loginAttemptServiceInit = func() login.LoginAttemptService {
		c.logger.Debug(c.module, "Initializing LoginAttemptService")
		return loginService.NewLoginAttemptServiceImpl(c.userRepo, c.loginAttemptRepo)
	}
	c.userServiceInit = func() users.UserService {
		c.logger.Debug(c.module, "Initializing UserService")
		return userService.NewUserServiceImpl(c.userRepo, c.getTokenService(), c.getLoginAttemptService())
	}
	c.passwordResetServiceInit = func() password.PasswordResetService {
		c.logger.Debug(c.module, "Initializing PasswordResetService")
		return passwordService.NewPasswordResetService(c.getTokenService(), c.userRepo, c.getPasswordResetEmailService())
	}
	c.clientServiceInit = func() client.ClientService {
		c.logger.Debug(c.module, "Initializing ClientService")
		return clientService.NewClientServiceImpl(c.clientRepo, c.getTokenService())
	}
	c.consentServiceInit = func() userConsent.UserConsentService {
		c.logger.Debug(c.module, "Initializing UserConsentService")
		return consentService.NewUserConsentServiceImpl(c.consentRepo, c.userRepo, c.getSessionService(), c.getClientService(), c.getAuthzCodeService())
	}
	c.authzCodeServiceInit = func() authzCode.AuthorizationCodeService {
		c.logger.Debug(c.module, "Initializing AuthorizationCodeService")
		return authzCodeService.NewAuthorizationCodeServiceImpl(c.authzCodeRepo, c.getUserService(), c.getClientService())
	}
	c.authorizationServiceInit = func() authz.AuthorizationService {
		c.logger.Debug(c.module, "Initializing AuthorizationService")
		return authzService.NewAuthorizationServiceImpl(c.getAuthzCodeService(), c.getConsentService(), c.getTokenService(), c.getClientService())
	}
	c.authServiceInit = func() auth.AuthenticationService {
		c.logger.Debug(c.module, "Initializing AuthenticationService")
		return authService.NewAuthenticationServiceImpl(c.getTokenService(), c.getClientService(), c.getUserService())
	}
	c.passwordResetEmailServiceInit = func() email.EmailService {
		c.logger.Debug(c.module, "Initializing PasswordResetEmailService")
		service, err := emailService.NewPasswordResetEmailService()
		if err != nil {
			panic(err)
		}
		return service
	}
	c.emailNotificationServiceInit = func() email.EmailService {
		c.logger.Debug(c.module, "Initializing EmailNotificationService")
		service, err := emailService.NewEmailNotificationService()
		if err != nil {
			panic(err)
		}
		return service
	}
}

// initializeHandlers initializes the HTTP handlers used by the service container.
func (c *ServiceContainer) initializeHandlers() {
	c.logger.Info(c.module, "Initializing handlers")
	c.userHandler = handlers.NewUserHandler(c.getUserService(), c.getPasswordResetService(), c.getSessionService())
	c.clientHandler = handlers.NewClientHandler(c.getClientService())
	c.tokenHandler = handlers.NewTokenHandler(c.getAuthService(), c.getSessionService(), c.getAuthorizationService())
	c.authzHandler = handlers.NewAuthorizationHandler(c.getAuthorizationService(), c.getSessionService())
	c.oauthHandler = handlers.NewOAuthHandler(c.getUserService(), c.getSessionService(), c.getClientService(), c.getConsentService(), c.getAuthzCodeService())
}

// initializeServerConfigs initializes the server-related configurations,
// including middleware, TLS configuration, and the HTTP server.
func (c *ServiceContainer) initializeServerConfigs() {
	c.logger.Info(c.module, "Initializing server configurations")
	c.middleware = middleware.NewMiddleware(c.getTokenService())
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
		Addr:         fmt.Sprintf(":%s", config.GetServerConfig().Port()),
		ReadTimeout:  config.GetServerConfig().ReadTimeout(),
		WriteTimeout: config.GetServerConfig().WriteTimeout(),
		TLSConfig:    tlsConfig,
	}
}

func (c *ServiceContainer) getTokenService() token.TokenService {
	c.tokenServiceOnce.Do(func() { c.tokenService = c.tokenServiceInit() })
	return c.tokenService
}

func (c *ServiceContainer) getSessionService() session.SessionService {
	c.sessionServiceOnce.Do(func() { c.sessionService = c.sessionServiceInit() })
	return c.sessionService
}

func (c *ServiceContainer) getUserService() users.UserService {
	c.userServiceOnce.Do(func() { c.userService = c.userServiceInit() })
	return c.userService
}

func (c *ServiceContainer) getAuthService() auth.AuthenticationService {
	c.authServiceOnce.Do(func() { c.authService = c.authServiceInit() })
	return c.authService
}

func (c *ServiceContainer) getLoginAttemptService() login.LoginAttemptService {
	c.loginAttemptServiceOnce.Do(func() { c.loginAttemptService = c.loginAttemptServiceInit() })
	return c.loginAttemptService
}

func (c *ServiceContainer) getClientService() client.ClientService {
	c.clientServiceOnce.Do(func() { c.clientService = c.clientServiceInit() })
	return c.clientService
}

func (c *ServiceContainer) getConsentService() userConsent.UserConsentService {
	c.consentServiceOnce.Do(func() { c.consentService = c.consentServiceInit() })
	return c.consentService
}

func (c *ServiceContainer) getAuthzCodeService() authzCode.AuthorizationCodeService {
	c.authzCodeServiceOnce.Do(func() { c.authzCodeService = c.authzCodeServiceInit() })
	return c.authzCodeService
}

func (c *ServiceContainer) getPasswordResetService() password.PasswordResetService {
	c.passwordResetServiceOnce.Do(func() { c.passwordResetService = c.passwordResetServiceInit() })
	return c.passwordResetService
}

func (c *ServiceContainer) getAuthorizationService() authz.AuthorizationService {
	c.authorizationServiceOnce.Do(func() { c.authorizationService = c.authorizationServiceInit() })
	return c.authorizationService
}

func (c *ServiceContainer) getPasswordResetEmailService() email.EmailService {
	c.passwordResetEmailOnce.Do(func() { c.passwordResetEmailService = c.passwordResetEmailServiceInit() })
	return c.passwordResetEmailService
}

func (c *ServiceContainer) getEmailNotificationService() email.EmailService {
	c.emailNotificationOnce.Do(func() { c.emailNotificationService = c.emailNotificationServiceInit() })
	return c.emailNotificationService
}

func (c *ServiceContainer) getHTTPSessionCookieService() cookie.HTTPCookieService {
	c.httpCookieServiceOnce.Do(func() { c.httpCookieService = c.httpCookieServiceInit() })
	return c.httpCookieService
}
