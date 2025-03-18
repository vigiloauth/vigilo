package client

import "github.com/vigiloauth/vigilo/internal/client"

// ClientService defines the interface for managing client registration.
type ClientService interface {
	// CreatePublicClient registers a new public client.
	//
	// Parameters:
	//   newClient *client.Client: The client to be registered.
	//
	// Returns:
	//   *client.ClientRegistrationResponse: The response containing client details.
	//   error: An error if the registration fails.
	CreatePublicClient(newClient *client.Client) (*client.ClientRegistrationResponse, error)
}
