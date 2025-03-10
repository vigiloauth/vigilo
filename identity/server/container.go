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

	"github.com/vigiloauth/vigilo/internal/email"
	"github.com/vigiloauth/vigilo/internal/middleware"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
)

type ServiceContainer struct {
	tokenBlacklist    token.TokenStore
	loginAttemptStore login.LoginAttemptStore

	passwordResetEmailService email.EmailService
	tokenManager              token.TokenManager
	sessionService            session.Session

	userStore            users.UserStore
	registrationService  registration.Registration
	authService          auth.Authentication
	passwordResetService password.PasswordReset
	userHandler          *handlers.UserHandler

	middleware *middleware.Middleware
	tlsConfig  *tls.Config
	httpServer *http.Server
}

func NewServiceContainer() *ServiceContainer {
	container := &ServiceContainer{}

	container.tokenBlacklist = token.GetInMemoryTokenStore()
	container.userStore = users.GetInMemoryUserStore()
	container.loginAttemptStore = login.NewInMemoryLoginAttemptStore()

	container.passwordResetEmailService, _ = email.NewPasswordResetEmailService()
	container.tokenManager = token.NewTokenService(container.tokenBlacklist)
	container.sessionService = session.NewSessionService(container.tokenManager, container.tokenBlacklist)
	container.passwordResetService = password.NewPasswordResetService(container.tokenManager, container.userStore, container.passwordResetEmailService)
	container.registrationService = registration.NewRegistrationService(container.userStore, container.tokenManager)
	container.authService = auth.NewAuthenticationService(container.userStore, container.loginAttemptStore, container.tokenManager)

	container.userHandler = handlers.NewUserHandler(container.registrationService, container.authService, container.passwordResetService, container.sessionService)
	container.middleware = middleware.NewMiddleware(container.tokenManager)

	container.tlsConfig = initializeTLSConfig()
	container.httpServer = initializeHTTPServer(container.tlsConfig)

	return container
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

func initializeHTTPServer(tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf(":%d", config.GetServerConfig().Port()),
		ReadTimeout:  config.GetServerConfig().ReadTimeout(),
		WriteTimeout: config.GetServerConfig().WriteTimeout(),
		TLSConfig:    tlsConfig,
	}
}
