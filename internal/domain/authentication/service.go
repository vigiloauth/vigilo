package domain

import (
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
)

// AuthenticationService defines methods for issuing OAuth 2.0 tokens
// through different authentication flows.
type AuthenticationService interface {
	// IssueClientCredentialsToken generates a token using the client credentials grant type.
	// This flow is typically used for machine-to-machine authentication where no user is involved.
	//
	// Parameters:
	//
	//   clientID: The registered client identifier
	//   clientSecret: The client's secret used for authentication
	//   requestedGrantType: The OAuth 2.0 grant type (should be "client_credentials")
	//   requestedScopes: Space-delimited list of requested scopes
	//
	// Returns:
	//
	//   A TokenResponse containing the generated access token and related metadata, or an error if token issuance fails
	IssueClientCredentialsToken(clientID, clientSecret, requestedGrantType, requestedScopes string) (*token.TokenResponse, error)

	// IssueResourceOwnerToken generates a token using the resource owner password credentials grant type.
	// This flow is used when the user provides their credentials directly to the client application.
	//
	// Parameters:
	//
	//   clientID: The registered client identifier
	//   clientSecret: The client's secret used for authentication
	//   requestedGrantType: The OAuth 2.0 grant type (should be "password")
	//   requestedScopes: Space-delimited list of requested scopes
	//   loginAttempt: User login details including username and password
	//
	// Returns:
	//
	//   A TokenResponse containing the generated access token and related metadata, or an error if token issuance fails
	IssueResourceOwnerToken(clientID, clientSecret, requestedGrantType, requestedScopes string, loginAttempt *user.UserLoginAttempt) (*token.TokenResponse, error)

	// RefreshAccessToken generates a new access token using a previously issued refresh token.
	// This method implements the OAuth 2.0 refresh token grant flow.
	//
	// Parameters:
	//
	//	clientID: The registered client identifier
	//	clientSecret: The client's secret used for authentication
	//	requestedGrantType: The OAuth 2.0 grant type (should be "refresh_token")
	//	refreshToken: The previously issued refresh token
	//  requestedScopes: The clients scopes.
	//
	// Returns:
	//
	//	A TokenResponse containing the newly generated access token and related metadata, or an error if token refresh fails
	RefreshAccessToken(clientID, clientSecret, requestedGrantType, refreshToken, requestedScopes string) (*token.TokenResponse, error)
}
