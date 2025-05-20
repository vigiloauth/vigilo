package domain

import (
	"context"

	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

// TokenRequestProcessor defines an interface for issuing token pairs.
type TokenRequestProcessor interface {
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
	//	- user *users.UserLoginAttempt: The user's login attempt information including credentials.
	//
	// Returns:
	//	- *TokenResponse: The response containing the issued token.
	//	- error: An error if authentication or token issuance fails.
	IssueResourceOwnerToken(ctx context.Context, clientID, clientSecret, grantType string, scopes types.Scope, user *users.UserLoginAttempt) (*TokenResponse, error)

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

	// ExchangeAuthorizationCodeForTokens creates access and refresh tokens based on a validated token exchange request.
	//
	// Parameters:
	//   - ctx Context: The context for managing timeouts and cancellations.
	//   - authCodeData *authz.AuthorizationCodeData: The authorization code data.
	//
	// Returns:
	//   - *token.TokenResponse: A fully formed token response with access and refresh tokens.
	//   - error: An error if token generation fails.
	ExchangeAuthorizationCodeForTokens(ctx context.Context, authCodeData *authz.AuthorizationCodeData) (*TokenResponse, error)
}
