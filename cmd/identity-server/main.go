package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	config "github.com/vigiloauth/vigilo/v2/cmd/config/application"
	lib "github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/idp/server"
)

func main() {
	isDockerENV := os.Getenv("VIGILO_SERVER_MODE") == "docker"
	if isDockerENV {
		cfg := config.LoadConfigurations() // This loads config from YAML/Env Vars

		var baseURL string = "/identity"
		var port string = ":8080"
		const module string = "Vigilo Identity Provider"
		var logger *lib.Logger = lib.GetLogger()
		var forceHTTPs bool = false
		var certFile string = ""
		var keyFile string = ""

		port = ":8080"
		logger = lib.GetLogger()
		logger.SetLevel("DEBUG")

		if cfg != nil && cfg.ServerConfig != nil {
			if cfg.Port != nil {
				port = fmt.Sprintf(":%s", *cfg.Port)
			}

			if cfg.ServerConfig.BaseURL != nil {
				baseURL = *cfg.ServerConfig.BaseURL
			}

			if cfg.ServerConfig.ForceHTTPS != nil {
				forceHTTPs = *cfg.ServerConfig.ForceHTTPS
			}
			if cfg.ServerConfig.CertFilePath != nil {
				certFile = *cfg.ServerConfig.CertFilePath
			}
			if cfg.ServerConfig.KeyFilePath != nil {
				keyFile = *cfg.ServerConfig.KeyFilePath
			}
			if cfg.Logger != nil {
				logger = cfg.Logger
			}
			if cfg.LogLevel != nil {
				logger.SetLevel(*cfg.LogLevel)
			}

		}

		if !strings.HasPrefix(baseURL, "/") {
			baseURL = "/" + baseURL
		}

		vs := server.NewVigiloIdentityServer()
		httpServer := vs.HTTPServer()
		r := chi.NewRouter()

		r.Route(baseURL, func(subRouter chi.Router) {
			subRouter.Mount("/", vs.Router())
		})

		logger.Info(module, "", "Starting the VigiloAuth Identity Provider on %s with base URL: %s", port, baseURL)

		if forceHTTPs {
			if certFile == "" || keyFile == "" {
				logger.Error(module, "", "HTTPS requested but certificate or key file path is not configured in YAML or loaded correctly. Exiting.")
				os.Exit(1)
			}
			logger.Info(module, "", "Attempting to start server on HTTPS...")
			if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil {
				logger.Error(module, "", "Failed to start server on HTTPS: %v", err)
				os.Exit(1)
			}
		} else {
			logger.Info(module, "", "Attempting to start server on HTTP...")
			if err := httpServer.ListenAndServe(); err != nil {
				logger.Error(module, "", "Failed to start server: %v", err)
				os.Exit(1)
			}
		}

		select {}
	}
}
