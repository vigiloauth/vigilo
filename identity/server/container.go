package server

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/handlers"
	auth "github.com/vigiloauth/vigilo/internal/auth/authentication"
	loginAttempt "github.com/vigiloauth/vigilo/internal/auth/loginattempt"
	passwordReset "github.com/vigiloauth/vigilo/internal/auth/passwordreset"
	registration "github.com/vigiloauth/vigilo/internal/auth/registration"
	session "github.com/vigiloauth/vigilo/internal/auth/session"

	"github.com/vigiloauth/vigilo/internal/email"
	"github.com/vigiloauth/vigilo/internal/middleware"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
)

type ServiceContainer struct {
	tokenBlacklist    token.TokenStore
	loginAttemptStore *loginAttempt.LoginAttemptStore

	passwordResetEmailService email.EmailService
	tokenService              *token.TokenService
	sessionService            *session.SessionService

	userStore         users.UserStore
	userRegistration  *registration.RegistrationService
	userLogin         *auth.AuthenticationService
	userPasswordReset *passwordReset.PasswordResetService
	userHandler       *handlers.UserHandler

	middleware *middleware.Middleware
	tlsConfig  *tls.Config
	httpServer *http.Server
}

func NewServiceContainer() *ServiceContainer {
	container := &ServiceContainer{}

	container.tokenBlacklist = token.GetInMemoryTokenStore()
	container.userStore = users.GetInMemoryUserStore()
	container.loginAttemptStore = loginAttempt.NewLoginAttemptStore()

	container.passwordResetEmailService, _ = email.NewPasswordResetEmailService()
	container.tokenService = token.NewTokenService(container.tokenBlacklist)
	container.sessionService = session.NewSessionService(container.tokenService, container.tokenBlacklist)
	container.userPasswordReset = passwordReset.NewPasswordResetService(container.tokenService, container.userStore, container.passwordResetEmailService)
	container.userRegistration = registration.NewRegistrationService(container.userStore, container.tokenService)
	container.userLogin = auth.NewAuthenticationService(container.userStore, container.loginAttemptStore, container.tokenService)

	container.userHandler = handlers.NewUserHandler(container.userRegistration, container.userLogin, container.userPasswordReset, container.sessionService)
	container.middleware = middleware.NewMiddleware(container.tokenService)

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
