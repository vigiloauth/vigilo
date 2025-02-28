package server

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/auth"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/token"
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
}

// NewVigiloIdentityServer creates and initializes a new instance of IdentityServer.
func NewVigiloIdentityServer(serverConfig *config.ServerConfig) *VigiloIdentityServer {
	if serverConfig == nil {
		serverConfig = config.NewDefaultServerConfig()
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
	}

	server.setupRoutes()
	if serverConfig.ForceHTTPS {
		server.router.Use(server.httpsRedirectMiddleware)
	}

	return server
}

// Router returns the pre-configured router instance for integration.
func (s *VigiloIdentityServer) Router() chi.Router {
	return s.router
}

func initializeUserHandler(serverConfig *config.ServerConfig) *handlers.UserHandler {
	userStore := users.GetInMemoryUserStore()
	loginAttemptStore := auth.NewLoginAttemptStore()
	userRegistration := users.NewUserRegistration(userStore, serverConfig.JWTConfig)
	userLogin := auth.NewUserLogin(userStore, loginAttemptStore, serverConfig)
	return handlers.NewUserHandler(userRegistration, userLogin, serverConfig.JWTConfig)
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
		Addr:         fmt.Sprintf(":%d", serverConfig.Port),
		ReadTimeout:  serverConfig.ReadTimeout,
		WriteTimeout: serverConfig.WriteTimeout,
		TLSConfig:    tlsConfig,
	}
}

func (s *VigiloIdentityServer) setupRoutes() {
	s.router.Use(middleware.Throttle(s.serverConfig.RequestsPerMinute))

	s.router.Post(utils.UserEndpoints.Registration, s.userHandler.Register)
	s.router.Post(utils.UserEndpoints.Login, s.userHandler.Login)

	s.router.Group(func(r chi.Router) {
		r.Use(s.authMiddleware())
		r.Post(utils.UserEndpoints.Logout, s.userHandler.Logout)
	})
}

func (s *VigiloIdentityServer) httpsRedirectMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			redirectToHttps(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func redirectToHttps(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	target := "https://" + host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusPermanentRedirect)
}

func (s *VigiloIdentityServer) authMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				utils.WriteError(w, errors.NewInvalidCredentialsError())
				return
			}

			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if token.GetTokenBlacklist().IsTokenBlacklisted(tokenString) {
				utils.WriteError(w, errors.NewInvalidCredentialsError())
				return
			}

			_, err := token.ParseJWT(tokenString, *s.serverConfig.JWTConfig)
			if err != nil {
				utils.WriteError(w, errors.NewInvalidCredentialsError())
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
