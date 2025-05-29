package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
	if !isDockerENV {
		return
	}

	cfg := config.LoadConfigurations()

	baseURL := "/identity"
	port := ":8080"
	module := "Vigilo Identity Provider"
	logger := lib.GetLogger()
	forceHTTPs := false
	certFile := ""
	keyFile := ""

	if cfg != nil && cfg.ServerConfig != nil {
		if cfg.Port != nil {
			port = fmt.Sprintf(":%s", *cfg.Port)
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

	vs := server.NewVigiloIdentityServer()
	r := chi.NewRouter()

	setupSpaRouting(r)

	httpServer := vs.HTTPServer()
	r.Route(baseURL, func(subRouter chi.Router) {
		subRouter.Mount("/", vs.Router())
	})
	httpServer.Handler = r

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Info(module, "", "Starting the VigiloAuth Identity Provider on %s with base URL: %s", port, baseURL)
		var err error
		if forceHTTPs {
			if certFile == "" || keyFile == "" {
				logger.Error(module, "", "HTTPS requested but certificate or key file path is not configured. Exiting.")
				os.Exit(1)
			}
			err = httpServer.ListenAndServeTLS(certFile, keyFile)
		} else {
			err = httpServer.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			logger.Error(module, "", "HTTP server error: %v", err)
			os.Exit(1)
		}
	}()

	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	vs.Shutdown()

	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error(module, "", "HTTP server shutdown error: %v", err)
	} else {
		logger.Info(module, "", "HTTP server shut down gracefully")
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
