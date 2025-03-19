package client

import "github.com/vigiloauth/vigilo/internal/client"

// ClientService defines the interface for managing client registration.
type ClientService interface {
	// SaveClient registers a new public client.
	//
	// Parameters:
	//
	//   newClient *client.Client: The client to be registered.
	//
	// Returns:
	//
	//   *client.ClientRegistrationResponse: The response containing client details.
	//   error: An error if the registration fails.
	SaveClient(newClient *client.Client) (*client.ClientRegistrationResponse, error)

	// RegenerateClientSecret regenerates a client secret.
	//
	// Parameters
	//
	//	clientID string: The ID of the client.
	//
	// Returns:
	//
	//  *client.ClientSecretRegenerationResponse: If successful
	//  error: An error if the regeneration fails.
	RegenerateClientSecret(clientID string) (*client.ClientSecretRegenerateResponse, error)
}
