package domain

import "context"

// ClientRepository defines the interface for storing and managing Clients.
type ClientRepository interface {
	// SaveClient adds a new client to the store if it does not already exist.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- client *Client: The client object to store.
	//
	// Returns:
	//	- error: An error if the client already exists, nil otherwise.
	SaveClient(ctx context.Context, client *Client) error

	// GetClientByID retrieves a client by its ID.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client to retrieve.
	//
	// Returns:
	//	- *Client: The client object if found, nil otherwise.
	//	- error: An error if retrieval fails.
	GetClientByID(ctx context.Context, clientID string) (*Client, error)

	// DeleteClient removes a client from the store by its ID.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client to delete.
	//
	// Returns:
	//	- error: Returns an error if deletion fails, otherwise false.
	DeleteClientByID(ctx context.Context, clientID string) error

	// UpdateClient updates an existing client in the store.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- client *Client: The updated client object.
	//
	// Returns:
	//	- error: An error if the client does not exist, nil otherwise.
	UpdateClient(ctx context.Context, client *Client) error

	// IsExistingID checks to see if an ID already exists in the database.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The client ID to verify.
	//
	// Returns:
	//	- bool: True if it exists, otherwise false.
	IsExistingID(ctx context.Context, clientID string) bool
}
