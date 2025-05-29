package domain

import (
	"context"
	"net/http"

	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

// TokenGrantProcessor defines an interface for issuing token pairs.
type TokenGrantProcessor interface {
	// IssueClientCredentialsToken issues a token using the Client Credentials grant type.
	//
	// Parameters:
	//	- ctx context.Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client requesting the token.
	//	- clientSecret string: The secret associated with the client.
	//	- grantType string: The OAuth2 grant type being used (must be "client_credentials").
	//	- scopes types.Scope: The scopes to associate with the issued token.
	//
	// Returns:
	//	- *TokenResponse: The response containing the issued token.
	//	- error: An error if token issuance fails.
	IssueClientCredentialsToken(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope) (*TokenResponse, error)

	// IssueResourceOwnerToken issues a token using the Resource Owner Password Credentials grant type.
	//
	// Parameters:
	//	- ctx context.Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client requesting the token.
	//	- clientSecret string: The secret associated with the client.
	//	- grantType string: The OAuth2 grant type being used (must be "password").
	//	- scopes types.Scope: The scopes to associate with the issued token.
	//	- user *users.UserLoginRequest: The user's login request containing their credentials.
	//
	// Returns:
	//	- *TokenResponse: The response containing the issued token.
	//	- error: An error if authentication or token issuance fails.
	IssueResourceOwnerToken(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope, user *users.UserLoginRequest) (*TokenResponse, error)

	// RefreshToken issues a new access token using a valid refresh token.
	//
	// Parameters:
	//	- ctx context.Context: The context for managing timeouts and cancellations.
	//	- clientID string: The ID of the client requesting the token.
	//	- clientSecret string: The secret associated with the client.
	//	- grantType string: The OAuth2 grant type being used (must be "refresh_token").
	//	- refreshToken string: The refresh token used to obtain a new access token.
	//	- scopes types.Scope: The scopes to associate with the new access token.
	//
	// Returns:
	//	- *TokenResponse: The response containing the new access token (and optionally a new refresh token).
	//	- error: An error if the refresh token is invalid or expired.
	RefreshToken(ctx context.Context, clientID, clientSecret, grantType, refreshToken string, scopes types.Scope) (*TokenResponse, error)

	// ExchangeAuthorizationCode creates access and refresh tokens based on a validated token exchange request.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - request *TokenRequest: The token request data.
	//
	// Returns:
	//   - *token.TokenResponse: A fully formed token response with access and refresh tokens.
	//   - error: An error if token generation fails.
	ExchangeAuthorizationCode(ctx context.Context, request *TokenRequest) (*TokenResponse, error)

	// IntrospectToken verifies the validity of a given token by introspecting its details.
	// This method checks whether the token is valid, expired, or revoked and returns the
	// associated token information if it is valid.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//	 - r *http.Request: The request for client authentication.
	//   - tokenStr string: The token to be introspected.
	//
	// Returns:
	//   - *TokenIntrospectionResponse: A struct containing token details such as
	//     validity, expiration, and any associated metadata. If the token is valid, this
	//     response will include all relevant claims associated with the token.
	// 	 error: An error if client authentication fails.
	IntrospectToken(ctx context.Context, r *http.Request, tokenStr string) (*TokenIntrospectionResponse, error)

	// RevokeToken handles revoking the given token. The token can either be an Access token or a Refresh token.
	// This method has no return values since the content of the response should be ignored by clients.
	// If an error occurs during the process, the errors will be logged.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//	 - r *http.Request: The request for client authentication.
	//   - tokenStr string: The token to be revoked.
	//
	// Returns:
	//	- error: An error if client authentication fails.
	RevokeToken(ctx context.Context, r *http.Request, tokenStr string) error
}
