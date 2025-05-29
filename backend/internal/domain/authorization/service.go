package domain

import (
	"context"

	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

// AuthorizationService defines the interface for handling client authorization requests.
type AuthorizationService interface {

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

	// UpdateAuthorizationCode updates the authorization code data in the database.
	//
	// Parameters:
	//	- ctx context.Context: The context for managing timeouts and cancellations.
	//	- authData *AuthorizationCodeData: The authorization code data to update.
	//
	// Returns:
	//	- error: An error if the update fails, otherwise nil.
	UpdateAuthorizationCode(ctx context.Context, authData *authz.AuthorizationCodeData) error
}
