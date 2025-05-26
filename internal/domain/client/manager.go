package domain

import "context"

type ClientManager interface {
	// RegenerateClientSecret regenerates the client secret for a given client ID.
	// It returns a response containing the new client secret and its expiration time.
	//
	// Parameters:
	// 	- ctx context.Context: The context for the operation.
	// 	- clientID string: The ID of the client for which to regenerate the secret.
	//
	// Returns:
	//	- *ClientSecretRegenerationResponse: A pointer to ClientSecretRegenerationResponse containing the new secret and expiration time.
	// 	- error: An error if the operation fails, or nil if successful.
	RegenerateClientSecret(ctx context.Context, clientID string) (*ClientSecretRegenerationResponse, error)

	// GetClientByID retrieves a client by its ID.
	//
	// Parameters:
	// 	- ctx context.Context: The context for the operation.
	// 	- clientID string: The ID of the client to retrieve.
	//
	// Returns:
	// 	- *Client: A pointer to the Client object if found, or nil if not found.
	// 	- error: An error if the operation fails, or nil if successful.
	GetClientByID(ctx context.Context, clientID string) (*Client, error)

	// GetClientInformation retrieves client information by client ID and registration access token.
	// It returns a response containing the client information.
	//
	// Parameters:
	// 	- ctx context.Context: The context for the operation.
	// 	- clientID string: The ID of the client to retrieve information for.
	// 	- registrationAccessToken string: The registration access token for authentication.
	//
	// Returns:
	// 	- *ClientInformationResponse: A pointer to ClientInformationResponse containing the client information.
	// 	- error: An error if the operation fails, or nil if successful.
	GetClientInformation(ctx context.Context, clientID string, registrationAccessToken string) (*ClientInformationResponse, error)

	// UpdateClientInformation updates the client information for a given client ID.
	//
	// Parameters:
	// 	- ctx context.Context: The context for the operation.
	// 	- clientID string: The ID of the client to update.
	// 	- registrationAccessToken string: The registration access token for authentication.
	// 	- request *ClientUpdateRequest: A pointer to ClientUpdateRequest containing the updated information.
	//
	// Returns:
	// 	- *ClientInformationResponse: A pointer to ClientInformationResponse containing the updated client information.
	// 	- error: An error if the operation fails, or nil if successful.
	UpdateClientInformation(ctx context.Context, clientID string, registrationAccessToken string, request *ClientUpdateRequest) (*ClientInformationResponse, error)

	// DeleteClientInformation deletes the client information for a given client ID.
	//
	// Parameters:
	// 	- ctx context.Context: The context for the operation.
	// 	- clientID string: The ID of the client to delete.
	// 	- registrationAccessToken string: The registration access token for authentication.
	//
	// Returns:
	// 	- error: An error if the operation fails, or nil if successful.
	DeleteClientInformation(ctx context.Context, clientID string, registrationAccessToken string) error
}
