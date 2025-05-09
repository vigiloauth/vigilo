package domain

import (
	"context"

	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

// AuthorizationService defines the interface for handling client authorization requests.
type AuthorizationService interface {
	// AuthorizeClient handles the authorization logic for a client request.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- authorizationRequest *ClientAuthorizationRequest: The client authorization request.
	//  - consentApproved: A boolean indicating whether the user has already approved consent for the requested scopes.
	//
	// Returns:
	//   - string: The redirect URL, or an empty string if authorization failed.
	//   - error: An error message, if any.
	//
	// This method performs the following steps:
	//  1. Checks if the user is authenticated.
	//  2. Verifies user consent if required or if already approved.
	//  3. Generates an authorization code if authorization is successful.
	//  4. Constructs the redirect URL with the authorization code or error parameters.
	//  5. Returns the success status, redirect URL and any error messages.
	//
	// Errors:
	//	- Returns an error message if the user is not authenticated, consent is denied, or authorization code generation fails.
	AuthorizeClient(ctx context.Context, authorizationRequest *client.ClientAuthorizationRequest, consentApproved bool) (string, error)

	// AuthorizeTokenExchange validates the token exchange request for an OAuth 2.0 authorization code grant.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- tokenRequest token.TokenRequest: The token exchange request containing client and authorization code details.
	//
	// Returns:
	//	- *AuthorizationCodeData: The authorization code data if authorization is successful.
	//	- error: An error if the token exchange request is invalid or fails authorization checks.
	AuthorizeTokenExchange(ctx context.Context, tokenRequest *token.TokenRequest) (*authz.AuthorizationCodeData, error)

	// GenerateTokens creates access and refresh tokens based on a validated token exchange request.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- authCodeData *authz.AuthorizationCodeData: The authorization code data.
	//
	// Returns:
	//	- *token.TokenResponse: A fully formed token response with access and refresh tokens.
	//	- error: An error if token generation fails.
	GenerateTokens(ctx context.Context, authCodeData *authz.AuthorizationCodeData) (*token.TokenResponse, error)

	// AuthorizeUserInfoRequest validates whether the provided access token claims grant sufficient
	// permission to access the /userinfo endpoint.
	//
	// This method is responsible for performing authorization checks and retrieving the user only. It does not validate the token itself (assumes
	// the token has already been validated by the time this method is called).
	//
	// Parameters:
	//	- ctx context.Context: The context for managing timeouts and cancellations.
	//	- claims *TokenClaims: The token claims extracted from the a valid access token. These claims should include the
	//		'scope' field, which will be used to verify whether the client is authorized for the request.
	//
	// Returns:
	//	- *User: The retrieved user if authorization succeeds, otherwise nil.
	//	- error: An error if authorization fails, otherwise nil.
	AuthorizeUserInfoRequest(ctx context.Context, claims *token.TokenClaims) (*users.User, error)
}
