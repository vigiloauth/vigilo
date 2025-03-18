package client

import "github.com/vigiloauth/vigilo/internal/client"

// ClientStore defines the interface for storing and managing Clients.
type ClientStore interface {
	// CreateClient adds a new client to the store if it does not already exist.
	//
	// Parameters:
	//
	//	client *client.Client: The client object to store.
	//
	// Returns:
	//
	//	error: An error if the client already exists, nil otherwise.
	CreateClient(client *client.Client) error

	// GetClient retrieves a client by its ID.
	//
	// Parameters:
	//
	//	clientID string: The ID of the client to retrieve.
	//
	// Returns:
	//
	//	*client.Client: The client object if found, nil otherwise.
	GetClient(clientID string) *client.Client

	// DeleteClient removes a client from the store by its ID.
	//
	// Parameters:
	//
	//	clientID string: The ID of the client to delete.
	//
	// Returns:
	//
	//	error: Returns an error if deletion fails, otherwise false.
	DeleteClient(clientID string) error

	// UpdateClient updates an existing client in the store.
	//
	// Parameters:
	//
	//	client *client.Client: The updated client object.
	//
	// Returns:
	//
	//	error: An error if the client does not exist, nil otherwise.
	UpdateClient(client *client.Client) error
}
