package domain

import "context"

// ClientService defines the interface for managing client registration.
type ClientService interface {
	// Register registers a new public client.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- newClient *Client: The client to be registered.
	//
	// Returns:
	//	- *ClientRegistrationResponse: The response containing client details.
	//	- error: An error if the registration fails.
	Register(ctx context.Context, newClient *Client) (*ClientRegistrationResponse, error)

	// RegenerateClientSecret regenerates a client secret.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client.
	//
	// Returns:
	//  - *ClientSecretRegenerationResponse: If successful
	//  - error: An error if the regeneration fails.
	RegenerateClientSecret(ctx context.Context, clientID string) (*ClientSecretRegenerationResponse, error)

	// GetClientByID retrieves a client by the given ID.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client.
	//
	// Returns:
	//	- client *Client: Returns the client if they exist, otherwise nil.
	//	- error: An error if retrieval fails.
	GetClientByID(ctx context.Context, clientID string) (*Client, error)

	// ValidateClientRedirectURI checks to see if the redirectURI exists based on
	// an existing client's saved redirectURIs
	//
	// Parameters:
	//	- redirectURI string: The redirectURI to validate against.
	//	- client *Client: The existing client.
	//
	// Returns:
	//	- error: Returns an error if the client does not contain the given redirectURI.
	ValidateClientRedirectURI(redirectURI string, existingClient *Client) error

	// ValidateAndRetrieveClient validates the provided registration access token, ensures the client exists,
	// revokes the token if necessary, and compares the token value to the clientID. It returns an error if any
	// validation fails or if the client cannot be retrieved.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- clientID: The ID of the client to validate and retrieve.
	//	- registrationAccessToken: The access token used for validation.
	//
	// Returns:
	//	- *CLientInformationResponse: If the the request is successful.
	//	- error: An error if validation fails or the client cannot be retrieved.
	ValidateAndRetrieveClient(ctx context.Context, clientID, registrationAccessToken string) (*ClientInformationResponse, error)

	// ValidateAndUpdateClient validates the provided registration access token, ensures the client exists,
	// revokes the token if necessary, and compares the token value to the clientID. It returns an error if any
	// validation fails or if the client cannot be updated.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client to validate and update.
	//	- registrationAccessToken string: The access token used for validation.
	//	- request *ClientUpdateRequest: The client update request.
	//
	// Returns:
	//	- *CLientInformationResponse: If the the request is successful.
	//	- error: An error if validation fails or the client cannot be updated.
	ValidateAndUpdateClient(ctx context.Context, clientID, registrationAccessToken string, request *ClientUpdateRequest) (*ClientInformationResponse, error)

	// ValidateAndDeleteClient validates the provided registration access token, ensures the client exists,
	// revokes the token if necessary, and compares the token value to the clientID. It returns an error if
	// any validation fails or the client cannot be deleted.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client to validate and delete.
	//	- registrationAccessToken string: The access token used for validation.
	//
	// Returns:
	//	- error: An error if validation fails or the client cannot be deleted.
	ValidateAndDeleteClient(ctx context.Context, clientID, registrationAccessToken string) error

	// AuthenticateClient authenticates the client using provided credentials
	// and authorizes access by validating required grant types and scopes.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client.
	//	- clientSecret string: The client secret.
	//	- requestedGrant string: The requested grant type to validate.
	//	- scopes string: The scopes to validate.
	//
	// Returns:
	//	- error: An error if authentication or authorization fails.
	AuthenticateClient(ctx context.Context, clientID string, clientSecret string, requestedGrant string, requestedScopes string) error
}
