package main

import (
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	config "github.com/vigiloauth/vigilo/cmd/config/application"
	"github.com/vigiloauth/vigilo/idp/server"
)

func main() {
	isDockerENV := os.Getenv("VIGILO_SERVER_MODE") == "docker"
	if isDockerENV {
		cfg := config.LoadConfigurations()
		module := cfg.Module
		logger := cfg.Logger

		vs := server.NewVigiloIdentityServer()
		r := chi.NewRouter()

		port := ":8080"
		baseURL := *cfg.ServerConfig.BaseURL
		r.Mount(baseURL, vs.Router())
		http.ListenAndServe(port, r)

		logger.Info(module, "Starting the VigiloAuth Server on :%s", port)
		logger.Info(module, "Using base URL: %s", baseURL)
	}
}
