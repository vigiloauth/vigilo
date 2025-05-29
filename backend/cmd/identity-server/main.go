package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	config "github.com/vigiloauth/vigilo/v2/cmd/config/application"
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

	config.LoadConfigurations()

	vs := server.NewVigiloIdentityServer()
	r := chi.NewRouter()

	setupSpaRouting(r)
	vs.StartServer(r)
	vs.Shutdown()
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
