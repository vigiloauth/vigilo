package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/crypto"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// Ensures that ClientServiceImpl implements the ClientService interface.
var _ client.ClientService = (*ClientServiceImpl)(nil)

// ClientServiceImpl provides the implementation of ClientService.
type ClientServiceImpl struct {
	clientRepo   client.ClientRepository
	tokenService token.TokenService
}

// NewClientServiceImpl creates a new instance of ClientServiceImpl.
//
// Parameters:
//
//	clientRepo ClientRepository: The client store to be used.
//
// Returns:
//
//	*ClientServiceImpl: A new instance of ClientServiceImpl.
func NewClientServiceImpl(
	clientRepo client.ClientRepository,
	tokenService token.TokenService,
) *ClientServiceImpl {
	return &ClientServiceImpl{
		clientRepo:   clientRepo,
		tokenService: tokenService,
	}
}

// Register registers a new public client.
//
// Parameters:
//
//	newClient *client.Client: The client to be registered.
//
// Returns:
//
//	*client.ClientRegistrationResponse: The response containing client details.
//	error: An error if registration fails.
func (cs *ClientServiceImpl) Register(newClient *client.Client) (*client.ClientRegistrationResponse, error) {
	clientID, err := cs.generateUniqueClientID()
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to generate client ID")
	}
	newClient.ID = clientID

	var plainSecret string
	if newClient.Type == client.Confidential {
		plainSecret, err = cs.generateClientSecret()
		if err != nil {
			return nil, errors.NewInternalServerError()
		}
		hashedSecret, err := crypto.HashString(plainSecret)
		if err != nil {
			return nil, errors.NewInternalServerError()
		}
		newClient.Secret = hashedSecret
		newClient.SecretExpiration = 0
	}

	newClient.CreatedAt, newClient.UpdatedAt = time.Now(), time.Now()
	if err := cs.clientRepo.SaveClient(newClient); err != nil {
		return nil, errors.Wrap(err, "", "failed to create new client")
	}

	accessToken, err := cs.tokenService.GenerateToken(newClient.ID, config.GetServerConfig().TokenConfig().AccessTokenDuration())
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to generate the registration access token")
	}

	response := &client.ClientRegistrationResponse{
		ID:                      newClient.ID,
		Name:                    newClient.Name,
		Type:                    newClient.Type,
		RedirectURIS:            newClient.RedirectURIS,
		GrantTypes:              newClient.GrantTypes,
		Scopes:                  newClient.Scopes,
		ResponseTypes:           newClient.ResponseTypes,
		CreatedAt:               newClient.CreatedAt,
		UpdatedAt:               newClient.UpdatedAt,
		TokenEndpointAuthMethod: newClient.TokenEndpointAuthMethod,
		RegistrationAccessToken: accessToken,
		ConfigurationEndpoint:   cs.buildClientConfigurationEndpoint(newClient.ID),
		IDIssuedAt:              time.Now(),
	}

	if newClient.Type == client.Confidential {
		response.Secret = plainSecret
	}

	return response, nil
}

// RegenerateClientSecret regenerates a client secret.
//
// Parameters
//
//	clientID string: The ID of the client.
//
// Returns:
//
//	*client.ClientSecretRegenerationResponse: If successful.
//	error: An error if the regeneration fails.
func (cs *ClientServiceImpl) RegenerateClientSecret(clientID string) (*client.ClientSecretRegenerationResponse, error) {
	if clientID == "" {
		return nil, errors.New(errors.ErrCodeEmptyInput, "missing required parameter: 'client_id'")
	}

	retrievedClient := cs.clientRepo.GetClientByID(clientID)
	if retrievedClient == nil {
		return nil, errors.New(errors.ErrCodeInvalidClient, "client does not exist with the given ID")
	}
	if err := cs.validateClientAuthorization(retrievedClient, "", client.ClientManage, client.ClientCredentials); err != nil {
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	clientSecret, err := cs.generateClientSecret()
	if err != nil {
		return nil, errors.Wrap(err, "", "error generating 'client_secret'")
	}

	retrievedClient.Secret, err = crypto.HashString(clientSecret)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to encrypt 'client_secret")
	}

	updatedAt := time.Now()
	retrievedClient.UpdatedAt = updatedAt
	if err := cs.clientRepo.UpdateClient(retrievedClient); err != nil {
		return nil, errors.Wrap(err, "", "failed to update client")
	}

	return &client.ClientSecretRegenerationResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		UpdatedAt:    updatedAt,
	}, nil
}

// AuthenticateClientForCredentialsGrant authenticates the client using provided credentials
// and authorizes access by validating required grant types and scopes.
//
// Parameters:
//
//	clientID string: The ID of the client.
//	clientSecret string: The client secret.
//
// Returns:
//
//	*client.Client: The authenticated client if successful.
//	error: An error if authentication or authorization fails.
func (cs *ClientServiceImpl) AuthenticateClientForCredentialsGrant(clientID, clientSecret string) (*client.Client, error) {
	if clientID == "" || clientSecret == "" {
		return nil, errors.New(errors.ErrCodeEmptyInput, "missing required parameter")
	}

	existingClient := cs.clientRepo.GetClientByID(clientID)
	if existingClient == nil {
		return nil, errors.New(errors.ErrCodeInvalidClient, "client does not exist with the given ID")
	}
	if err := cs.validateClientAuthorization(existingClient, clientSecret, client.ClientManage, client.ClientCredentials); err != nil {
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	return existingClient, nil
}

// GetClientByID retrieves a client by the given ID.
//
// Parameters:
//
//	clientID string: The ID of the client.
//
// Returns:

// client *client.Client: Returns the client if they exist, otherwise nil.
func (cs *ClientServiceImpl) GetClientByID(clientID string) *client.Client {
	return cs.clientRepo.GetClientByID(clientID)
}

// ValidateClientRedirectURI checks to see if the redirectURI exists based on
// an existing client's saved redirectURIs
//
// Parameters:
//
//	redirectURI string: The redirectURI to validate against.
//	existingClient *client.Client: The existing client.
//
// Returns:
//
//	error: Returns an error if the client does not contain the given redirectURI.
func (cs *ClientServiceImpl) ValidateClientRedirectURI(redirectURI string, existingClient *client.Client) error {
	if redirectURI == "" || existingClient == nil {
		return errors.New(errors.ErrCodeInvalidRequest, "one or more parameters are empty")
	}

	isValidRedirectURI, err := cs.isValidURIFormat(redirectURI, existingClient.Type)
	if !isValidRedirectURI {
		return errors.Wrap(err, "", fmt.Sprintf("an error occurred validating the redirectURI: %s", redirectURI))
	}

	if !existingClient.HasRedirectURI(redirectURI) {
		return errors.New(errors.ErrCodeInvalidRequest, "invalid redirect_uri")
	}

	return nil
}

// ValidateAndRetrieveClient validates the provided registration access token, ensures the client exists,
// revokes the token if necessary, and compares the token value to the clientID. It returns an error if any
// validation fails or if the client cannot be retrieved.
//
// Parameters:
//
//	clientID: The ID of the client to validate and retrieve.
//	registrationAccessToken: The access token used for validation.
//
// Returns:
//
//	*CLientInformationResponse: If the the request is successful.
//	error: An error if validation fails or the client cannot be retrieved.
func (cs *ClientServiceImpl) ValidateAndRetrieveClient(clientID, registrationAccessToken string) (*client.ClientInformationResponse, error) {
	if clientID == "" || registrationAccessToken == "" {
		return nil, errors.NewMissingParametersError()
	}

	retrievedClient, err := cs.validateClientAndToken(clientID, registrationAccessToken, client.ClientRead)
	if err != nil {
		return nil, err
	}

	registrationClientURI := config.GetServerConfig().BaseURL() + web.ClientEndpoints.Register
	return client.NewClientInformationResponse(
		retrievedClient.ID,
		retrievedClient.Secret,
		registrationClientURI,
		registrationAccessToken,
	), nil
}

// ValidateAndUpdateClient validates the provided registration access token, ensures the client exists,
// revokes the token if necessary, and compares the token value to the clientID. It returns an error if any
// validation fails or if the client cannot be updated.
//
// Parameters:
//
//	clientID string: The ID of the client to validate and update.
//	registrationAccessToken string: The access token used for validation.
//	request *ClientUpdateRequest: The client update request.
//
// Returns:
//
//	*CLientInformationResponse: If the the request is successful.
//	error: An error if validation fails or the client cannot be updated.
func (cs *ClientServiceImpl) ValidateAndUpdateClient(clientID, registrationAccessToken string, request *client.ClientUpdateRequest) (*client.ClientInformationResponse, error) {
	if clientID == "" || registrationAccessToken == "" {
		return nil, errors.NewMissingParametersError()
	}

	if request.ID != clientID {
		return nil, errors.New(errors.ErrCodeUnauthorized, "the provided client ID is invalid or does not match the registered credentials")
	}

	retrievedClient, err := cs.validateClientAndToken(clientID, registrationAccessToken, client.ClientManage)
	if err != nil {
		return nil, err
	}

	if retrievedClient.Type == client.Confidential {
		request.Type = client.Confidential
		if err := request.Validate(); err != nil {
			return nil, err
		} else if request.Secret != "" && request.Secret != retrievedClient.Secret {
			return nil, errors.New(errors.ErrCodeUnauthorized, "the provided client secret is invalid or does not match the registered credentials")
		}
	}

	retrievedClient.UpdateValues(request)
	if err := cs.clientRepo.UpdateClient(retrievedClient); err != nil {
		return nil, err
	}

	registrationClientURI := config.GetServerConfig().BaseURL() + web.ClientEndpoints.Register
	return client.NewClientInformationResponse(
		retrievedClient.ID,
		retrievedClient.Secret,
		registrationClientURI,
		registrationAccessToken,
	), nil
}

// validateClientAuthorization checks if the client is authorized to perform certain actions
// based on its configuration, including its type, client secret, grant type, and scope.
// Note: If the client secret is not needed for validation, it can be passed as and empty string.
//
// Parameters:
//
//	existingClient *Client: The client whose authorization is being validated.
//	clientSecret string: The client secret to validate against the stored value.
//	scope string: The client scope(s) to validate against the stored value.
//	grantType string: The client grant type to validate against the stored value.
//
// Returns:
//
//	error: An error indicating why the client is not authorized, or nil if the client is valid.
func (cs *ClientServiceImpl) validateClientAuthorization(existingClient *client.Client, clientSecret, scope, grantType string) error {
	if !existingClient.IsConfidential() {
		return errors.New(errors.ErrCodeUnauthorizedClient, "client is not confidential")
	}

	if clientSecret != "" {
		if !existingClient.SecretsMatch(clientSecret) {
			return errors.New(errors.ErrCodeInvalidClient, "the client credentials are invalid or incorrectly formatted")
		}
	}

	if !existingClient.HasScope(scope) {
		return errors.New(errors.ErrCodeInsufficientScope, "client does not have the required scope(s)")
	}
	if !existingClient.HasGrantType(grantType) {
		return errors.New(errors.ErrCodeInvalidGrant, "client does not have the required grant type")
	}
	return nil
}

func (cs *ClientServiceImpl) validateClientAndToken(clientID, registrationAccessToken, scope string) (*client.Client, error) {
	retrievedClient := cs.GetClientByID(clientID)
	if retrievedClient == nil {
		return nil, cs.revokeTokenAndReturnError(registrationAccessToken, errors.ErrCodeUnauthorized, "the provided client ID is invalid")
	} else if !retrievedClient.HasScope(scope) && !retrievedClient.HasScope(client.ClientManage) {
		return nil, cs.revokeTokenAndReturnError(registrationAccessToken, errors.ErrCodeInsufficientScope, "client does not have the required scopes for this request")
	}

	tokenClaim, err := cs.tokenService.ParseToken(registrationAccessToken)
	if err != nil {
		return nil, cs.revokeTokenAndReturnError(registrationAccessToken, errors.ErrCodeInvalidToken, "failed to parse registration access token")
	} else if tokenClaim.Subject != clientID {
		return nil, cs.revokeTokenAndReturnError(registrationAccessToken, errors.ErrCodeUnauthorized, "the registration access token subject does not match with the client ID in the request")
	} else if time.Now().Unix() > tokenClaim.ExpiresAt {
		return nil, cs.revokeTokenAndReturnError(registrationAccessToken, errors.ErrCodeUnauthorized, "the registration access token has expired")
	}

	return retrievedClient, nil
}

// generateUniqueClientID generates a unique client ID, ensuring it is not already in use.
// The method has a 100 Millisecond delay between each retry, and will retry max 5 times.
//
// Returns:
//
//	string: The generated unique client ID.
//	error: An error if the ID generation fails after multiple retries.
func (cs *ClientServiceImpl) generateUniqueClientID() (string, error) {
	const maxRetries = 5
	const retryDelay = 100 * time.Millisecond

	for range maxRetries {
		clientID := crypto.GenerateUUID()
		if !cs.clientRepo.IsExistingID(clientID) {
			return clientID, nil
		}
		time.Sleep(retryDelay)
	}

	return "", errors.New(errors.ErrCodeInternalServerError, "failed to generate a unique client ID after multiple retries")
}

// generateClientSecret generates a unique client secret, making sure it is not already in use.
//
// Returns:
//
//	string: The generated client secret.
//	error: An error if the client secret fails after multiple retries.
func (cs *ClientServiceImpl) generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", errors.NewInternalServerError()
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// isValidURI format validates if the given redirectURI is valid.
//
// Parameters:
//
//	uri string: The uri to validate.
//	clientType client.ClientType: The type of client (public or confidential).
//
// Returns:
//
//	bool: True if URI is valid, otherwise false.
//	error: If an error occurs while validating the URI.
func (cs *ClientServiceImpl) isValidURIFormat(uri string, clientType string) (bool, error) {
	parsedURL, err := cs.parseURI(uri)
	if err != nil {
		return false, errors.Wrap(err, "", "invalid redirect URI format")
	}

	if err := cs.validateRedirectURIScheme(parsedURL); err != nil {
		return false, errors.Wrap(err, "", "failed to validate URL scheme")
	}

	switch clientType {
	case client.Public:
		if err := cs.validatePublicClientURIScheme(parsedURL); err != nil {
			return false, errors.Wrap(err, "", "failed to valid public client redirect URI")
		}
	case client.Confidential:
		if err := cs.validateConfidentialClientURIScheme(parsedURL); err != nil {
			return false, errors.Wrap(err, "", "failed to valid confidential client redirect URI")
		}
	default:
		return false, errors.New(errors.ErrCodeInvalidClient, "invalid client type: must be confidential or public")
	}

	return true, nil
}

// parseURI parses the given URI string into a URL object and checks its validity.
//
// Parameters:
//
//	uri string: The URI to parse and validate.
//
// Returns:
//
//	*url.URL: A parsed URL object if successful.
//	error: An error if the URI format is invalid or if fragments are present.
func (cs *ClientServiceImpl) parseURI(uri string) (*url.URL, error) {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRedirectURI, "invalid redirect URI format")
	}

	if parsedURL.Fragment != "" {
		return nil, errors.New(errors.ErrCodeInvalidRedirectURI, "fragments are not allowed in the redirect URI")
	}

	return parsedURL, nil
}

// validateRedirectURIScheme validates the scheme of a parsed URL to ensure it meets the required conditions.
//
// Parameters:
//
//	parsedURL *url.URL: The parsed URL to validate.
//
// Returns:
//
//	error: An error if the scheme is not valid, or nil if the scheme is valid.
func (cs *ClientServiceImpl) validateRedirectURIScheme(parsedURL *url.URL) error {
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" && !strings.HasPrefix(parsedURL.Scheme, "custom") {
		return errors.New(
			errors.ErrCodeInvalidRedirectURI,
			"invalid scheme, must be 'https' or 'http' for localhost or 'custom' for mobile",
		)
	}
	return nil
}

// validatePublicClientURIScheme validates the URL scheme for public clients.
//
// Parameters:
//
//	parsedURL *url.URL: The parsed URL to validate.
//
// Returns:
//
//	error: An error if the public client URL scheme is invalid, or nil if it is valid.
func (cs *ClientServiceImpl) validatePublicClientURIScheme(parsedURL *url.URL) error {
	if parsedURL.Scheme == "http" && parsedURL.Host != "localhost" {
		return errors.New(errors.ErrCodeInvalidRedirectURI, "'http' scheme is only allowed for 'localhost'")
	}
	if parsedURL.Scheme == "https" && parsedURL.Host == "localhost" {
		return errors.New(
			errors.ErrCodeInvalidRedirectURI,
			"'https' scheme is not allowed for for public clients using 'localhost'",
		)
	}

	return nil
}

// validateConfidentialClientURIScheme validates the URL scheme for confidential clients.
//
// Parameters:
//
//	parsedURL *url.URL: The parsed URL to validate.
//
// Returns:
//
//	error: An error if the confidential client URL scheme is invalid, or nil if it is valid.
func (cs *ClientServiceImpl) validateConfidentialClientURIScheme(parsedURL *url.URL) error {
	if strings.Contains(parsedURL.Host, "*") {
		return errors.New(errors.ErrCodeInvalidRedirectURI, "wildcards are not allowed for confidential clients")
	}
	return nil
}

func (cs *ClientServiceImpl) revokeTokenAndReturnError(token, errorCode, errorMessage string) error {
	if err := cs.tokenService.DeleteToken(token); err != nil {
		return errors.New(errors.ErrCodeInternalServerError, "failed to revoke registration access token")
	}
	return errors.New(errorCode, errorMessage)
}

func (cs *ClientServiceImpl) buildClientConfigurationEndpoint(clientID string) string {
	baseURL := config.GetServerConfig().BaseURL()
	return fmt.Sprintf("%s%s/%s", baseURL, web.ClientEndpoints.ClientConfiguration, clientID)
}
