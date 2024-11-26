package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/users"
)

// VigiloIdentityServer represents the identity server responsible for handling HTTP requests related to user management.
type VigiloIdentityServer struct {
	Router      chi.Router
	userHandler *handlers.UserHandler
}

// NewVigiloIdentityServer creates and initializes a new instance of the VigiloIdentityServer.
// It sets up the necessary routes and dependencies.
func NewVigiloIdentityServer() *VigiloIdentityServer {
	userStore := users.GetInMemoryUserStore()
	server := &VigiloIdentityServer{
		Router:      chi.NewRouter(),
		userHandler: handlers.NewUserHandler(userStore),
	}
	server.setUpRoutes()
	return server
}

// setUpRoutes sets up the HTTP routes for the identity server, mapping specific endpoints to handler functions.
func (s *VigiloIdentityServer) setUpRoutes() {
	s.Router.Post(users.UserEndpoints.Registration, s.userHandler.HandleUserRegistration)
}
