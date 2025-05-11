package domain

import (
	"context"
	"net/http"
)

// UserConsentService defines the interface for managing user consent operations
// in the OAuth2 authorization flow.
type UserConsentService interface {
	// CheckUserConsent verifies if a user has previously granted consent to a client
	// for the requested scope.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The unique identifier of the user.
	//	- clientID string: The identifier of the client application requesting access.
	//	- scope string: The space-separated list of permissions being requested.
	//
	// Returns:
	//	- bool: True if consent exists, false if consent is needed.
	//	- error: An error if the consent check operation fails.
	CheckUserConsent(ctx context.Context, userID, clientID, scope string) (bool, error)

	// SaveUserConsent records a user's consent for a client application
	// to access resources within the specified scope.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The unique identifier of the user granting consent.
	//	- clientID string: The identifier of the client application receiving consent.
	//	- scope string: The space-separated list of permissions being granted.
	//
	// Returns:
	//	- error: An error if the consent cannot be saved, or nil if successful.
	SaveUserConsent(ctx context.Context, userID, clientID, scope string) error

	// RevokeConsent removes a user's consent for a client.
	//
	// Parameters:
	//  - ctx Context: The context for managing timeouts and cancellations.
	//	- userID string: The ID of the user.
	//	- clientID string: The ID of the client application.
	//
	// Returns:
	//	- error: An error if the consent cannot be revoked, or nil if successful.
	RevokeConsent(ctx context.Context, userID, clientID string) error

	// GetConsentDetails retrieves the details required for the user consent process.
	//
	// This method fetches information about the client application and the requested scopes,
	// and prepares the response to be displayed to the user for consent.
	//
	// Parameters:
	//   - userID string: The unique identifier of the user.
	//   - clientID string: The identifier of the client application requesting access.
	//   - redirectURI string: The redirect URI provided by the client application.
	//   - scope string: The space-separated list of permissions being requested.
	//   - r *http.Request: The HTTP request containing session and other metadata.
	//
	// Returns:
	//   - *consent.UserConsentResponse: The response containing client and scope details for the consent process.
	//   - error: An error if the details cannot be retrieved or prepared.
	GetConsentDetails(userID, clientID, redirectURI, state, scope, responseType, nonce, display string, r *http.Request) (*UserConsentResponse, error)

	// ProcessUserConsent processes the user's decision for the consent request.
	//
	// This method handles the user's approval or denial of the requested scopes,
	// stores the consent decision if approved, and generates the appropriate response
	// (e.g., an authorization code or an error redirect).
	//
	// Parameters:
	//   - userID string: The unique identifier of the user.
	//   - clientID string: The identifier of the client application requesting access.
	//   - redirectURI string: The redirect URI provided by the client application.
	//   - scope string: The space-separated list of permissions being requested.
	//   - consentRequest *consent.UserConsentRequest: The user's consent decision and approved scopes.
	//   - r *http.Request: The HTTP request containing session and other metadata.
	//
	// Returns:
	//   - *consent.UserConsentResponse: The response containing the result of the consent process (e.g., success or denial).
	//   - error: An error if the consent decision cannot be processed or stored.
	ProcessUserConsent(userID, clientID, redirectURI, scope string, consentRequest *UserConsentRequest, r *http.Request) (*UserConsentResponse, error)
}
