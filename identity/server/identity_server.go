package server

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/handlers"
	"github.com/vigiloauth/vigilo/internal/users"
	"net/http"
)

const defaultPort = "8080"

// VigiloIdentityServer represents the identity server responsible for handling HTTP requests related to user management.
type VigiloIdentityServer struct {
	Router      chi.Router
	Port        string
	userHandler *handlers.UserHandler
}

// NewVigiloIdentityServer creates and initializes a new instance of the VigiloIdentityServer.
// It sets up the necessary routes and dependencies.
func NewVigiloIdentityServer(port string) *VigiloIdentityServer {
	userStore := users.GetInMemoryUserStore()
	if port == "" {
		port = defaultPort
	}
	server := &VigiloIdentityServer{
		Router:      chi.NewRouter(),
		Port:        port,
		userHandler: handlers.NewUserHandler(userStore),
	}
	server.setUpRoutes()
	return server
}

// setUpRoutes sets up the HTTP routes for the identity server, mapping specific endpoints to handler functions.
func (s *VigiloIdentityServer) setUpRoutes() {
	s.Router.Post(users.UserEndpoints.Registration, s.userHandler.HandleUserRegistration)
}

// Start starts the Vigilo Identity Server, listening for incoming HTTP requests on the specified port.
func (s *VigiloIdentityServer) Start() {
	fmt.Printf("Starting Vigilo Identity Server on port %s\n", s.Port)
	if err := http.ListenAndServe(":"+s.Port, s.Router); err != nil {
		fmt.Printf("Error starting Vigilo Identity Server on port %s\n", s.Port)
	}
}
