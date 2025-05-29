package container

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/vigiloauth/vigilo/v2/idp/config"
)

type ServerConfigRegistry struct {
	tlsConfig  *tls.Config
	httpServer *http.Server
}

func NewServerConfigRegistry(services *ServiceRegistry) *ServerConfigRegistry {
	sr := &ServerConfigRegistry{}
	sr.initServerConfigurations()
	return sr
}

func (sr *ServerConfigRegistry) HTTPServer() *http.Server {
	return sr.httpServer
}

func (sr *ServerConfigRegistry) initServerConfigurations() {
	sr.initTLS()
	sr.initHTTPServer()
}

func (sr *ServerConfigRegistry) initTLS() {
	sr.tlsConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
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
