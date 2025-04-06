package domain

// ClientRepository defines the interface for storing and managing Clients.
type ClientRepository interface {
	// SaveClient adds a new client to the store if it does not already exist.
	//
	// Parameters:
	//
	//	client *Client: The client object to store.
	//
	// Returns:
	//
	//	error: An error if the client already exists, nil otherwise.
	SaveClient(client *Client) error

	// GetClientByID retrieves a client by its ID.
	//
	// Parameters:
	//
	//	clientID string: The ID of the client to retrieve.
	//
	// Returns:
	//
	//	*Client: The client object if found, nil otherwise.
	GetClientByID(clientID string) *Client

	// DeleteClient removes a client from the store by its ID.
	//
	// Parameters:
	//
	//	clientID string: The ID of the client to delete.
	//
	// Returns:
	//
	//	error: Returns an error if deletion fails, otherwise false.
	DeleteClientByID(clientID string) error

	// UpdateClient updates an existing client in the store.
	//
	// Parameters:
	//
	//	client *Client: The updated client object.
	//
	// Returns:
	//
	//	error: An error if the client does not exist, nil otherwise.
	UpdateClient(client *Client) error

	// IsExistingID checks to see if an ID already exists in the database.
	//
	// Parameters:
	//
	//	clientID string: The client ID to verify.
	//
	// Returns:
	//
	//	bool: True if it exists, otherwise false.
	IsExistingID(clientID string) bool
}
