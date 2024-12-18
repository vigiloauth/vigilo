package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/users"
	"net/http"
)

// VigiloIdentityServer represents the identity library's functionality.
type VigiloIdentityServer struct {
	router      chi.Router
	userHandler *handlers.UserHandler
}

// NewVigiloIdentityServer creates and initializes a new instance of IdentityServer.
func NewVigiloIdentityServer(useHTTPS bool) *VigiloIdentityServer {
	userStore := users.GetInMemoryUserStore()
	userRegistration := users.NewUserRegistration(userStore)
	userHandler := handlers.NewUserHandler(userRegistration)

	server := &VigiloIdentityServer{
		router:      chi.NewRouter(),
		userHandler: userHandler,
	}

	server.setupRoutes(useHTTPS)
	return server
}

// Router returns the pre-configured router instance for integration.
func (s *VigiloIdentityServer) Router() chi.Router {
	return s.router
}

func (s *VigiloIdentityServer) setupRoutes(useHTTPS bool) {
	if useHTTPS {
		s.router.Use(enforceHTTPS)
	}
	s.router.Post(users.UserEndpoints.Registration, s.userHandler.HandleUserRegistration)
}

// enforceHTTPS blocks all non-HTTPS requests.
func enforceHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "HTTPS required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
