package domain

import (
	"net/http"

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

	// IntrospectToken verifies the validity of a given token by introspecting its details.
	// This method checks whether the token is valid, expired, or revoked and returns the
	// associated token information if it is valid.
	//
	// Parameters:
	//
	//   token (string): The token to be introspected.
	//
	// Returns:
	//
	//   *TokenIntrospectionResponse: A struct containing token details such as
	//     validity, expiration, and any associated metadata. If the token is valid, this
	//     response will include all relevant claims associated with the token.
	IntrospectToken(token string) *token.TokenIntrospectionResponse

	// AuthenticateClientRequest validates the provided Authorization header.
	// It supports both "Basic" and "Bearer" authentication schemes.
	//
	// For "Basic" authentication, it decodes the base64-encoded credentials
	// and checks that the client ID and secret are correctly formatted.
	//
	// For "Bearer" authentication, it validates the token structure and
	// verifies its authenticity (e.g., signature, expiry, and claims).
	//
	// Returns an error if the header is malformed, the credentials are invalid,
	// or the token fails validation.
	AuthenticateClientRequest(r *http.Request) error
}
