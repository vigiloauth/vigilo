package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	config "github.com/vigiloauth/vigilo/v2/cmd/config/application"
	lib "github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/idp/server"
)

func main() {
	isDockerENV := os.Getenv("VIGILO_SERVER_MODE") == "docker"
	if isDockerENV {
		cfg := config.LoadConfigurations()

		var baseURL string
		var port string
		var module string
		var logger *lib.Logger
		var forceHTTPs bool
		var certFile string
		var keyFile string

		if cfg == nil || cfg.ServerConfig.BaseURL == nil || cfg.Port == nil || cfg.ServerConfig.ForceHTTPS != nil || cfg.ServerConfig.CertFilePath != nil || cfg.ServerConfig.KeyFilePath != nil {
			port = ":8080"
			logger = lib.GetLogger()
			logger.SetLevel("DEBUG")
			module = "Vigilo Identity Provider"
			baseURL = "/identity"
			forceHTTPs = false
		} else {
			baseURL = *cfg.ServerConfig.BaseURL
			port = fmt.Sprintf(":%s", *cfg.Port)
			module = cfg.Module
			logger = cfg.Logger
			forceHTTPs = *cfg.ServerConfig.ForceHTTPS
			keyFile = *cfg.ServerConfig.KeyFilePath
			certFile = *cfg.ServerConfig.CertFilePath
		}

		vs := server.NewVigiloIdentityServer()
		r := chi.NewRouter()

		r.Route(baseURL, func(subRouter chi.Router) {
			subRouter.Mount("/", vs.Router())
		})

		logger.Info(module, "", "Starting the VigiloAuth Identity Provider on %s with base URL: %s", port, baseURL)
		if forceHTTPs {
			if err := http.ListenAndServeTLS(port, certFile, keyFile, r); err != nil {
				logger.Error(module, "", "Failed to start server on HTTPS: %v", err)
			}
		} else {
			if err := http.ListenAndServe(port, r); err != nil {
				logger.Error(module, "", "Failed to start server: %v", err)
			}
		}
	}
}
