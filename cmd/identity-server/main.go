package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	config "github.com/vigiloauth/vigilo/v2/cmd/config/application"
	lib "github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/idp/server"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

func main() {
	isDockerENV := os.Getenv(constants.VigiloServerModeENV) == "docker"
	if isDockerENV {
		cfg := config.LoadConfigurations()

		var baseURL string = "/identity"
		var port string = ":8080"
		const module string = "Vigilo Identity Provider"
		var logger *lib.Logger = lib.GetLogger()
		var forceHTTPs bool = false
		var certFile string = ""
		var keyFile string = ""

		logger = lib.GetLogger()

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
		r := chi.NewRouter()

		setupSpaRouting(r)
		setupServer(logger, vs, port, baseURL, certFile, keyFile, module, forceHTTPs, r)

		select {}
	}
}

func setupServer(logger *lib.Logger, vs *server.VigiloIdentityServer, port, baseURL, certFile, keyFile, module string, forceHTTPs bool, r *chi.Mux) {
	httpServer := vs.HTTPServer()
	r.Route(baseURL, func(subRouter chi.Router) {
		subRouter.Mount("/", vs.Router())
	})

	httpServer.Handler = r
	logger.Info(module, "", "Starting the VigiloAuth Identity Provider on %s with base URL: %s", port, baseURL)
	if forceHTTPs {
		if certFile == "" || keyFile == "" {
			logger.Error(module, "", "HTTPS requested but certificate or key file path is not configured in YAML or loaded correctly. Exiting.")
			os.Exit(1)
		}
		if err := httpServer.ListenAndServeTLS(certFile, keyFile); err != nil {
			logger.Error(module, "", "Failed to start server on HTTPS: %v", err)
			os.Exit(1)
		}
	} else {
		if err := httpServer.ListenAndServe(); err != nil {
			logger.Error(module, "", "Failed to start server: %v", err)
			os.Exit(1)
		}
	}
}

func setupSpaRouting(r *chi.Mux) {
	buildPath := os.Getenv(constants.ReactBuildPathENV)
	fs := http.FileServer(http.Dir(buildPath))

	r.HandleFunc("/static/*", func(w http.ResponseWriter, r *http.Request) {
		filePath := strings.TrimPrefix(r.URL.Path, "/static/")
		fullPath := filepath.Join(buildPath, "static", filePath)

		_, err := os.Stat(fullPath)
		if os.IsNotExist(err) {
			web.WriteError(w, errors.New(errors.ErrCodeInternalServerError, "file not found"))
			return
		}

		setContentTypeHeader(w, fullPath)
		http.ServeFile(w, r, fullPath)
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(buildPath, "index.html"))
	})

	r.Get("/authenticate", serveIndexHTML(buildPath))
	r.Get("/consent", serveIndexHTML(buildPath))
	r.Get("/error", serveIndexHTML(buildPath))

	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for _, prefix := range []string{"/authenticate/", "/consent/", "/error/"} {
			if strings.HasPrefix(path, prefix+"static/") {
				staticPath := strings.TrimPrefix(path, prefix)
				r.URL.Path = "/" + staticPath
				fs.ServeHTTP(w, r)
				return
			}
		}

		http.ServeFile(w, r, filepath.Join(buildPath, "index.html"))
	})
}

func serveIndexHTML(buildPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(buildPath, "index.html"))
	}
}

func setContentTypeHeader(w http.ResponseWriter, fullPath string) {
	ext := filepath.Ext(fullPath)
	switch ext {
	case ".js":
		w.Header().Set("Content-Type", "application/javascript")
	case ".css":
		w.Header().Set("Content-Type", "text/css")
	case ".json":
		w.Header().Set("Content-Type", "application/json")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".jpg", ".jpeg":
		w.Header().Set("Content-Type", "image/jpeg")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	}
}
