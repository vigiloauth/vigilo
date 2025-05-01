package container

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/middleware"
)

type ServerConfigRegistry struct {
	services   *ServiceRegistry
	middleware LazyInit[*middleware.Middleware]
	tlsConfig  *tls.Config
	httpServer *http.Server

	logger *config.Logger
	module string
}

func NewServerConfigRegistry(logger *config.Logger, services *ServiceRegistry) *ServerConfigRegistry {
	module := "Server Config Registry"
	logger.Info(module, "", "Initializing Server Configs")

	sr := &ServerConfigRegistry{
		logger:   logger,
		module:   module,
		services: services,
	}

	sr.initServerConfigurations()
	return sr
}

func (sr *ServerConfigRegistry) initServerConfigurations() {
	sr.initMiddleware()
	sr.initTLS()
	sr.initHTTPServer()
}

func (sr *ServerConfigRegistry) Middleware() *middleware.Middleware {
	return sr.middleware.Get()
}

func (sr *ServerConfigRegistry) initMiddleware() {
	sr.logger.Debug(sr.module, "", "Initializing Middleware")
	sr.middleware = LazyInit[*middleware.Middleware]{
		initFunc: func() *middleware.Middleware {
			return middleware.NewMiddleware(sr.services.TokenService())
		},
	}
}

func (sr *ServerConfigRegistry) initTLS() {
	sr.logger.Debug(sr.module, "", "Initializing TLS")
	sr.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}
}

func (sr *ServerConfigRegistry) initHTTPServer() {
	sr.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%s", config.GetServerConfig().Port()),
		ReadTimeout:  config.GetServerConfig().ReadTimeout(),
		WriteTimeout: config.GetServerConfig().WriteTimeout(),
		TLSConfig:    sr.tlsConfig,
	}
}
