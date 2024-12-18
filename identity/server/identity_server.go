package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/users"
)

// VigiloIdentityServer represents the identity library's functionality.
type VigiloIdentityServer struct {
	router      chi.Router
	userHandler *handlers.UserHandler
}

// NewVigiloIdentityServer creates and initializes a new instance of IdentityServer.
// Automatically sets up routes.
func NewVigiloIdentityServer() *VigiloIdentityServer {
	userStore := users.GetInMemoryUserStore()
	userRegistration := users.NewUserRegistration(userStore)
	userHandler := handlers.NewUserHandler(userRegistration)

	server := &VigiloIdentityServer{
		router:      chi.NewRouter(),
		userHandler: userHandler,
	}

	server.setupRoutes()
	return server
}

func (s *VigiloIdentityServer) setupRoutes() {
	s.router.Post(users.UserEndpoints.Registration, s.userHandler.HandleUserRegistration)
}

// Router returns the pre-configured router instance for integration.
func (s *VigiloIdentityServer) Router() chi.Router {
	return s.router
}
