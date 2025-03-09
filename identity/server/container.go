package server

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/auth"
	"github.com/vigiloauth/vigilo/internal/middleware"
	"github.com/vigiloauth/vigilo/internal/token"
	"github.com/vigiloauth/vigilo/internal/users"
)

type ServiceContainer struct {
	tokenService      *token.TokenService
	tokenBlacklist    token.TokenBlacklist
	userStore         users.UserStore
	loginAttemptStore *auth.LoginAttemptStore
	sessionService    *auth.SessionService
	userRegistration  *users.UserRegistration
	userLogin         *users.UserLogin
	userHandler       *handlers.UserHandler
	middleware        *middleware.Middleware
	tlsConfig         *tls.Config
	httpServer        *http.Server
}

func NewServiceContainer() *ServiceContainer {
	container := &ServiceContainer{}

	container.tokenService = token.NewTokenService()
	container.tokenBlacklist = token.GetTokenBlacklist()
	container.userStore = users.GetInMemoryUserStore()
	container.loginAttemptStore = auth.NewLoginAttemptStore()

	container.sessionService = auth.NewSessionService(container.tokenService, container.tokenBlacklist)
	container.userRegistration = users.NewUserRegistration(container.userStore, container.tokenService)
	container.userLogin = users.NewUserLogin(container.userStore, container.loginAttemptStore, container.tokenService)

	container.userHandler = handlers.NewUserHandler(container.userRegistration, container.userLogin, container.sessionService)
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
