package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/idp/handlers"
	"github.com/vigiloauth/vigilo/internal/background"
	audit "github.com/vigiloauth/vigilo/internal/domain/audit"
	auth "github.com/vigiloauth/vigilo/internal/domain/authentication"
	authzCode "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	cookie "github.com/vigiloauth/vigilo/internal/domain/cookies"
	email "github.com/vigiloauth/vigilo/internal/domain/email"
	login "github.com/vigiloauth/vigilo/internal/domain/login"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	userConsent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/middleware"

	auditEventRepo "github.com/vigiloauth/vigilo/internal/repository/audit"
	authzCodeRepo "github.com/vigiloauth/vigilo/internal/repository/authzcode"
	clientRepo "github.com/vigiloauth/vigilo/internal/repository/client"
	loginRepo "github.com/vigiloauth/vigilo/internal/repository/login"
	sessionRepo "github.com/vigiloauth/vigilo/internal/repository/session"
	tokenRepo "github.com/vigiloauth/vigilo/internal/repository/token"
	userRepo "github.com/vigiloauth/vigilo/internal/repository/user"
	consentRepo "github.com/vigiloauth/vigilo/internal/repository/userconsent"

	authz "github.com/vigiloauth/vigilo/internal/domain/authorization"
	auditLogger "github.com/vigiloauth/vigilo/internal/service/audit"
	authService "github.com/vigiloauth/vigilo/internal/service/authentication"
	authzService "github.com/vigiloauth/vigilo/internal/service/authorization"
	authzCodeService "github.com/vigiloauth/vigilo/internal/service/authzcode"
	clientService "github.com/vigiloauth/vigilo/internal/service/client"
	cookieService "github.com/vigiloauth/vigilo/internal/service/cookies"
	emailService "github.com/vigiloauth/vigilo/internal/service/email"
	loginService "github.com/vigiloauth/vigilo/internal/service/login"
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
	auditEventRepo   audit.AuditRepository

	// Lazy-loaded services using sync.Once to ensure thread safety
	tokenServiceOnce         sync.Once
	sessionServiceOnce       sync.Once
	userServiceOnce          sync.Once
	clientServiceOnce        sync.Once
	consentServiceOnce       sync.Once
	authzCodeServiceOnce     sync.Once
	loginAttemptServiceOnce  sync.Once
	authorizationServiceOnce sync.Once
	httpCookieServiceOnce    sync.Once
	authServiceOnce          sync.Once
	emailServiceOnce         sync.Once
	mailerOnce               sync.Once
	auditLoggerOnce          sync.Once

	tokenService         token.TokenService
	sessionService       session.SessionService
	userService          users.UserService
	clientService        client.ClientService
	consentService       userConsent.UserConsentService
	authzCodeService     authzCode.AuthorizationCodeService
	loginAttemptService  login.LoginAttemptService
	authorizationService authz.AuthorizationService
	httpCookieService    cookie.HTTPCookieService
	authService          auth.AuthenticationService
	emailService         email.EmailService
	mailer               email.Mailer
	auditLogger          audit.AuditLogger

	tokenServiceInit         func() token.TokenService
	sessionServiceInit       func() session.SessionService
	userServiceInit          func() users.UserService
	clientServiceInit        func() client.ClientService
	consentServiceInit       func() userConsent.UserConsentService
	authzCodeServiceInit     func() authzCode.AuthorizationCodeService
	loginAttemptServiceInit  func() login.LoginAttemptService
	authorizationServiceInit func() authz.AuthorizationService
	httpCookieServiceInit    func() cookie.HTTPCookieService
	authServiceInit          func() auth.AuthenticationService
	emailServiceInit         func() email.EmailService
	mailerInit               func() email.Mailer
	auditLoggerInit          func() audit.AuditLogger

	userHandler   *handlers.UserHandler
	clientHandler *handlers.ClientHandler
	tokenHandler  *handlers.TokenHandler
	authzHandler  *handlers.AuthorizationHandler
	oauthHandler  *handlers.OAuthHandler

	middleware *middleware.Middleware
	tlsConfig  *tls.Config
	httpServer *http.Server

	schedulerCtx    context.Context
	schedulerCancel context.CancelFunc
	scheduler       *background.Scheduler

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
		module: "Service Container",
	}
	container.initializeInMemoryRepositories()
	container.initializeServices()
	container.initializeHandlers()
	container.initializeServerConfigs()
	container.initializeSchedulers()
	return container
}

// initializeInMemoryRepositories initializes the in-memory data stores used by the service container.
func (c *ServiceContainer) initializeInMemoryRepositories() {
	c.logger.Info(c.module, "", "Initializing in memory repositories")
	c.tokenRepo = tokenRepo.GetInMemoryTokenRepository()
	c.userRepo = userRepo.GetInMemoryUserRepository()
	c.loginAttemptRepo = loginRepo.GetInMemoryLoginRepository()
	c.clientRepo = clientRepo.GetInMemoryClientRepository()
	c.consentRepo = consentRepo.GetInMemoryUserConsentRepository()
	c.authzCodeRepo = authzCodeRepo.GetInMemoryAuthorizationCodeRepository()
	c.sessionRepo = sessionRepo.GetInMemorySessionRepository()
	c.auditEventRepo = auditEventRepo.GetInMemoryAuditEventRepository()
}

// initializeServices defines getter methods for lazy service initialization**
func (c *ServiceContainer) initializeServices() {
	c.logger.Info(c.module, "", "Initializing services")
	c.httpCookieServiceInit = func() cookie.HTTPCookieService {
		c.logger.Debug(c.module, "", "Initializing HTTPCookieService")
		return cookieService.NewHTTPCookieService()
	}
	c.tokenServiceInit = func() token.TokenService {
		c.logger.Debug(c.module, "", "Initializing TokenService")
		return tokenService.NewTokenService(c.tokenRepo)
	}
	c.sessionServiceInit = func() session.SessionService {
		c.logger.Debug(c.module, "", "Initializing SessionService")
		return sessionService.NewSessionService(c.getTokenService(), c.sessionRepo, c.getHTTPSessionCookieService(), c.getAuditLogger())
	}
	c.loginAttemptServiceInit = func() login.LoginAttemptService {
		c.logger.Debug(c.module, "", "Initializing LoginAttemptService")
		return loginService.NewLoginAttemptService(c.userRepo, c.loginAttemptRepo)
	}
	c.userServiceInit = func() users.UserService {
		c.logger.Debug(c.module, "", "Initializing UserService")
		return userService.NewUserService(c.userRepo, c.getTokenService(), c.getLoginAttemptService(), c.getEmailService(), c.getAuditLogger())
	}
	c.clientServiceInit = func() client.ClientService {
		c.logger.Debug(c.module, "", "Initializing ClientService")
		return clientService.NewClientService(c.clientRepo, c.getTokenService())
	}
	c.consentServiceInit = func() userConsent.UserConsentService {
		c.logger.Debug(c.module, "", "Initializing UserConsentService")
		return consentService.NewUserConsentService(c.consentRepo, c.userRepo, c.getSessionService(), c.getClientService(), c.getAuthzCodeService())
	}
	c.authzCodeServiceInit = func() authzCode.AuthorizationCodeService {
		c.logger.Debug(c.module, "", "Initializing AuthorizationCodeService")
		return authzCodeService.NewAuthorizationCodeService(c.authzCodeRepo, c.getUserService(), c.getClientService())
	}
	c.authorizationServiceInit = func() authz.AuthorizationService {
		c.logger.Debug(c.module, "", "Initializing AuthorizationService")
		return authzService.NewAuthorizationService(c.getAuthzCodeService(), c.getConsentService(), c.getTokenService(), c.getClientService())
	}
	c.authServiceInit = func() auth.AuthenticationService {
		c.logger.Debug(c.module, "", "Initializing AuthenticationService")
		return authService.NewAuthenticationService(c.getTokenService(), c.getClientService(), c.getUserService())
	}
	c.emailServiceInit = func() email.EmailService {
		c.logger.Debug(c.module, "", "Initializing EmailService")
		return emailService.NewEmailService(c.getGoMailer())
	}
	c.mailerInit = func() email.Mailer {
		c.logger.Debug(c.module, "", "Initializing GoMailer")
		return emailService.NewGoMailer()
	}
	c.auditLoggerInit = func() audit.AuditLogger {
		c.logger.Debug(c.module, "", "Initializing AuditLogger")
		return auditLogger.NewAuditLogger(c.auditEventRepo)
	}
}

// initializeHandlers initializes the HTTP handlers used by the service container.
func (c *ServiceContainer) initializeHandlers() {
	c.logger.Info(c.module, "", "Initializing handlers")
	c.userHandler = handlers.NewUserHandler(c.getUserService(), c.getSessionService())
	c.clientHandler = handlers.NewClientHandler(c.getClientService())
	c.tokenHandler = handlers.NewTokenHandler(c.getAuthService(), c.getSessionService(), c.getAuthorizationService())
	c.authzHandler = handlers.NewAuthorizationHandler(c.getAuthorizationService(), c.getSessionService())
	c.oauthHandler = handlers.NewOAuthHandler(c.getUserService(), c.getSessionService(), c.getClientService(), c.getConsentService(), c.getAuthzCodeService())
}

// initializeServerConfigs initializes the server-related configurations,
// including middleware, TLS configuration, and the HTTP server.
func (c *ServiceContainer) initializeServerConfigs() {
	c.logger.Info(c.module, "", "Initializing server configurations")
	c.middleware = middleware.NewMiddleware(c.getTokenService())
	c.tlsConfig = initializeTLSConfig()
	c.httpServer = initializeHTTPServer(c.tlsConfig)
}

func (c *ServiceContainer) initializeSchedulers() {
	c.logger.Info(c.module, "", "Initializing schedulers and worker pools")

	// Store the context and cancel function
	c.schedulerCtx, c.schedulerCancel = context.WithCancel(context.Background())
	c.scheduler = background.NewScheduler()

	healthCheckInterval := 5 * time.Minute
	queueProcessorInterval := 1 * time.Minute
	smtpJobs := background.NewSMTPJobs(c.getEmailService(), healthCheckInterval, queueProcessorInterval)
	c.scheduler.RegisterJob("SMTP Health Check", smtpJobs.RunHealthCheck)
	c.scheduler.RegisterJob("Email Retry Queue", smtpJobs.RunRetryQueueProcessor)

	tokenDeletionInterval := 5 * time.Minute
	tokenJobs := background.NewTokenJobs(c.getTokenService(), tokenDeletionInterval)
	c.scheduler.RegisterJob("Expired Token Deletion", tokenJobs.DeleteExpiredTokens)

	userDeletionInterval := 24 * time.Hour
	userJobs := background.NewUserJobs(c.getUserService(), userDeletionInterval)
	c.scheduler.RegisterJob("Unverified User Deletion", userJobs.DeleteUnverifiedUsers)

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		go c.scheduler.StartJobs(c.schedulerCtx)

		select {
		case <-sigCh:
			c.schedulerCancel()
		case <-c.schedulerCtx.Done():
		}

		signal.Stop(sigCh)
		c.scheduler.Wait()
	}()
}

func (c *ServiceContainer) Shutdown() {
	c.logger.Info(c.module, "", "Shutting down schedulers and worker pool")
	if c.schedulerCancel != nil {
		c.schedulerCancel()
	}

	if c.scheduler != nil {
		c.scheduler.Wait()
	}
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

func (c *ServiceContainer) getAuthorizationService() authz.AuthorizationService {
	c.authorizationServiceOnce.Do(func() { c.authorizationService = c.authorizationServiceInit() })
	return c.authorizationService
}

func (c *ServiceContainer) getHTTPSessionCookieService() cookie.HTTPCookieService {
	c.httpCookieServiceOnce.Do(func() { c.httpCookieService = c.httpCookieServiceInit() })
	return c.httpCookieService
}

func (c *ServiceContainer) getEmailService() email.EmailService {
	c.emailServiceOnce.Do(func() { c.emailService = c.emailServiceInit() })
	return c.emailService
}

func (c *ServiceContainer) getGoMailer() email.Mailer {
	c.mailerOnce.Do(func() { c.mailer = c.mailerInit() })
	return c.mailer
}

func (c *ServiceContainer) getAuditLogger() audit.AuditLogger {
	c.auditLoggerOnce.Do(func() { c.auditLogger = c.auditLoggerInit() })
	return c.auditLogger
}
