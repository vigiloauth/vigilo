package domain

import (
	"context"
	"net/http"

	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
)

// AuthenticationService defines methods for issuing OAuth 2.0 tokens
// through different authentication flows.
type AuthenticationService interface {
	// IssueClientCredentialsToken generates a token using the client credentials grant type.
	// This flow is typically used for machine-to-machine authentication where no user is involved.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The registered client identifier.
	//	- clientSecret string: The client's secret used for authentication.
	//	- requestedGrantType string: The OAuth 2.0 grant type (should be "client_credentials").
	//	- requestedScopes string: Space-delimited list of requested scopes.
	//
	// Returns:
	//	- *TokenResponse: A TokenResponse containing the generated access token and related metadata, or an error if token issuance fails.
	IssueClientCredentialsToken(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string) (*token.TokenResponse, error)

	// IssueResourceOwnerToken generates a token using the resource owner password credentials grant type.
	// This flow is used when the user provides their credentials directly to the client application.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The registered client identifier.
	//	- clientSecret string: The client's secret used for authentication.
	//	- requestedGrantType string: The OAuth 2.0 grant type (should be "password").
	//	- requestedScopes string: Space-delimited list of requested scopes.
	//	- loginAttempt *UserLoginAttempts: User login details including username and password.
	//
	// Returns:
	//	- *TokenResponse: A TokenResponse containing the generated access token and related metadata, or an error if token issuance fails.
	IssueResourceOwnerToken(ctx context.Context, clientID, clientSecret, requestedGrantType, requestedScopes string, loginAttempt *user.UserLoginAttempt) (*token.TokenResponse, error)

	// RefreshAccessToken generates a new access token using a previously issued refresh token.
	// This method implements the OAuth 2.0 refresh token grant flow.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- clientID string: The registered client identifier.
	//	- clientSecret string: The client's secret used for authentication.
	//	- requestedGrantType string: The OAuth 2.0 grant type (should be "refresh_token").
	//	- refreshToken string: The previously issued refresh token.
	//	- requestedScopes string: The clients scopes.
	//
	// Returns:
	//	- *TokenResponse: A TokenResponse containing the newly generated access token and related metadata, or an error if token refresh fails.
	RefreshAccessToken(ctx context.Context, clientID, clientSecret, requestedGrantType, refreshToken, requestedScopes string) (*token.TokenResponse, error)

	// IntrospectToken verifies the validity of a given token by introspecting its details.
	// This method checks whether the token is valid, expired, or revoked and returns the
	// associated token information if it is valid.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token to be introspected.
	//
	// Returns:
	//	- *TokenIntrospectionResponse: A struct containing token details such as
	//	validity, expiration, and any associated metadata. If the token is valid, this
	//	response will include all relevant claims associated with the token.
	IntrospectToken(ctx context.Context, token string) *token.TokenIntrospectionResponse

	// AuthenticateClientRequest validates the provided Authorization header.
	// It supports both "Basic" and "Bearer" authentication schemes.
	//
	// For "Basic" authentication, it decodes the base64-encoded credentials
	// and checks that the client ID and secret are correctly formatted.
	//
	// For "Bearer" authentication, it validates the token structure and
	// verifies its authenticity (e.g., signature, expiry, and claims).
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- scope string: The clients scopes.
	//
	// Returns:
	//	- error: Returns an error if the header is malformed, the credentials are invalid,
	//	or the token fails validation.
	AuthenticateClientRequest(ctx context.Context, r *http.Request, scope string) error

	// RevokeToken handles revoking the given token. The token can either be an Access token or a Refresh token.
	// This method has no return values since the content of the response should be ignored by clients.
	// If an error occurs during the process, the errors will be logged.
	//
	// Parameters:
	//	- ctx Context: The context for managing timeouts and cancellations.
	//	- token string: The token to be revoked.
	RevokeToken(ctx context.Context, token string)
}
