package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/handlers"
)

// VigiloIdentityServer represents the identity server responsible for handling HTTP requests related to user management.
type VigiloIdentityServer struct {
	Router      chi.Router
	userHandler *handlers.UserHandler
}

// NewVigiloIdentityServer creates and initializes a new instance of the VigiloIdentityServer.
// It sets up the necessary routes and dependencies.
func NewVigiloIdentityServer() *VigiloIdentityServer {
	server := &VigiloIdentityServer{
		Router:      chi.NewRouter(),
		userHandler: handlers.NewUserHandler(),
	}
	server.setUpRoutes()
	return server
}

// setUpRoutes sets up the HTTP routes for the identity server, mapping specific endpoints to handler functions.
func (s *VigiloIdentityServer) setUpRoutes() {
	s.Router.Post("/vigilo/identity/users", s.userHandler.HandleUserRegistration)
}
