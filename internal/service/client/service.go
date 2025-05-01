package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

// Ensures that ClientServiceImpl implements the ClientService interface.
var _ client.ClientService = (*clientService)(nil)

// clientService provides the implementation of ClientService.
type clientService struct {
	clientRepo   client.ClientRepository
	tokenService token.TokenService

	logger *config.Logger
	module string
}

// NewClientService creates a new instance of ClientServiceImpl.
//
// Parameters:
//   - clientRepo ClientRepository: The client store to be used.
//
// Returns:
//   - *ClientServiceImpl: A new instance of ClientServiceImpl.
func NewClientService(
	clientRepo client.ClientRepository,
	tokenService token.TokenService,
) client.ClientService {
	return &clientService{
		clientRepo:   clientRepo,
		tokenService: tokenService,
		logger:       config.GetServerConfig().Logger(),
		module:       "Client Service",
	}
}

// Register registers a new public client.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - newClient *Client: The client to be registered.
//
// Returns:
//   - *ClientRegistrationResponse: The response containing client details.
//   - error: An error if the registration fails.
func (cs *clientService) Register(ctx context.Context, newClient *client.Client) (*client.ClientRegistrationResponse, error) {
	requestID := utils.GetRequestID(ctx)

	clientID, err := cs.generateUniqueClientID(ctx)
	if err != nil {
		cs.logger.Error(cs.module, requestID, "[Register]: Failed to generate client ID: %v", err)
		return nil, errors.Wrap(err, "", "failed to generate client ID")
	}
	newClient.ID = constants.ClientIDPrefix + clientID

	var plainSecret string
	if newClient.Type == client.Confidential {
		plainSecret, err = cs.generateClientSecret()
		if err != nil {
			cs.logger.Error(cs.module, requestID, "[Register]: Failed to generate client secret: %v", err)
			return nil, errors.NewInternalServerError()
		}
		hashedSecret, err := crypto.HashString(plainSecret)
		if err != nil {
			cs.logger.Error(cs.module, requestID, "[Register]: Failed to encrypt client secret: %v", err)
			return nil, errors.NewInternalServerError()
		}
		newClient.Secret = hashedSecret
		newClient.SecretExpiration = 0
	}

	newClient.CreatedAt, newClient.UpdatedAt = time.Now(), time.Now()
	if err := cs.clientRepo.SaveClient(ctx, newClient); err != nil {
		cs.logger.Error(cs.module, requestID, "[Register]: Failed to save client: %v", err)
		return nil, errors.Wrap(err, "", "failed to create new client")
	}

	accessToken, err := cs.tokenService.GenerateToken(
		ctx, newClient.ID,
		strings.Join(newClient.Scopes, " "),
		"", config.GetServerConfig().TokenConfig().AccessTokenDuration(),
	)

	if err != nil {
		cs.logger.Error(cs.module, requestID, "[Register]: Failed to generate registration access token: %v", err)
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

	if newClient.IsConfidential() {
		response.Secret = plainSecret
		response.RegistrationAccessToken, err = cs.tokenService.EncryptToken(ctx, accessToken)
		if err != nil {
			return nil, err
		}
	}
	if newClient.JwksURI != "" {
		response.JwksURI = newClient.JwksURI
	}
	if newClient.LogoURI != "" {
		response.LogoURI = newClient.LogoURI
	}

	return response, nil
}

// RegenerateClientSecret regenerates a client secret.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client.
//
// Returns:
//   - *ClientSecretRegenerationResponse: If successful
//   - error: An error if the regeneration fails.
func (cs *clientService) RegenerateClientSecret(ctx context.Context, clientID string) (*client.ClientSecretRegenerationResponse, error) {
	requestID := utils.GetRequestID(ctx)

	if clientID == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "missing required parameter: 'client_id'")
		cs.logger.Error(cs.module, requestID, "[RegenerateClientSecret]: Failed to regenerate client secret for client=[%s]: %v", utils.TruncateSensitive(clientID), err)
		return nil, err
	}

	retrievedClient, err := cs.clientRepo.GetClientByID(ctx, clientID)
	if err != nil {
		cs.logger.Error(cs.module, requestID, "[RegenerateClientSecret]: An error occurred retrieving the client: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInvalidClient, "failed to retrieve client")
	}

	if !retrievedClient.IsConfidential() {
		return nil, errors.New(errors.ErrCodeInvalidClient, "invalid credentials")
	}

	if err := cs.validateClientAuthorization(retrievedClient, retrievedClient.Secret, constants.ClientCredentials, constants.ClientManage); err != nil {
		cs.logger.Error(cs.module, requestID, "[RegenerateClientSecret]: Failed to validate client=[%s]: %v", utils.TruncateSensitive(clientID), err)
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	clientSecret, err := cs.generateClientSecret()
	if err != nil {
		cs.logger.Error(cs.module, requestID, "[RegenerateClientSecret]: Failed to regenerate client secret: %v", err)
		return nil, errors.Wrap(err, "", "error generating 'client_secret'")
	}

	retrievedClient.Secret, err = crypto.HashString(clientSecret)
	if err != nil {
		cs.logger.Error(cs.module, requestID, "[RegenerateClientSecret]: Failed to encrypt client secret: %v", err)
		return nil, errors.Wrap(err, "", "failed to encrypt 'client_secret")
	}

	updatedAt := time.Now()
	retrievedClient.UpdatedAt = updatedAt
	if err := cs.clientRepo.UpdateClient(ctx, retrievedClient); err != nil {
		cs.logger.Error(cs.module, requestID, "[RegenerateClientSecret]: Failed to update client=[%s]: %v", utils.TruncateSensitive(clientID), err)
		return nil, errors.Wrap(err, "", "failed to update client")
	}

	cs.logger.Info(cs.module, requestID, "[RegenerateClientSecret]: Client successfully updated at=[%s]", updatedAt)
	return &client.ClientSecretRegenerationResponse{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		UpdatedAt:    updatedAt,
	}, nil
}

// AuthenticateClient authenticates the client using provided credentials
// and authorizes access by validating required grant types and scopes.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client.
//   - clientSecret string: The client secret.
//   - requestedGrant string: The requested grant type to validate.
//   - scopes string: The scopes to validate.
//
// Returns:
//   - error: An error if authentication or authorization fails.
func (cs *clientService) AuthenticateClient(ctx context.Context, clientID string, clientSecret string, requestedGrant string, requestedScopes string) error {
	requestID := utils.GetRequestID(ctx)

	existingClient, err := cs.clientRepo.GetClientByID(ctx, clientID)
	if err != nil {
		cs.logger.Error(cs.module, requestID, "[AuthenticateClient]: An error occurred retrieving the client: %v", err)
		return errors.Wrap(err, errors.ErrCodeInvalidClient, "failed to retrieve client")
	}

	if err := cs.validateClientAuthorization(existingClient, clientSecret, requestedGrant, requestedScopes); err != nil {
		cs.logger.Error(cs.module, requestID, "[AuthenticateClient]: Failed to validate client authorization: %v", err)
		return errors.Wrap(err, "", "failed to validate client authorization")
	}

	return nil
}

// GetClientByID retrieves a client by the given ID.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client.
//
// Returns:
//   - client *Client: Returns the client if they exist, otherwise nil.
//   - error: An error if retrieval fails.
func (cs *clientService) GetClientByID(ctx context.Context, clientID string) (*client.Client, error) {
	return cs.clientRepo.GetClientByID(ctx, clientID)
}

// ValidateClientRedirectURI checks to see if the redirectURI exists based on
// an existing client's saved redirectURIs
//
// Parameters:
//   - redirectURI string: The redirectURI to validate against.
//   - client *Client: The existing client.
//
// Returns:
//   - error: Returns an error if the client does not contain the given redirectURI.
func (cs *clientService) ValidateClientRedirectURI(redirectURI string, existingClient *client.Client) error {
	isValidRedirectURI, err := cs.isValidURIFormat(redirectURI, existingClient.Type)
	if !isValidRedirectURI {
		cs.logger.Error(cs.module, "[ValidateClientRedirectURI]: [%s] is not a valid URI", redirectURI)
		return errors.Wrap(err, "", fmt.Sprintf("an error occurred validating the redirectURI: %s", redirectURI))
	}

	if !existingClient.HasRedirectURI(redirectURI) {
		cs.logger.Error(cs.module, "[ValidateClientRedirectURI]: Client=[%s] does not have requested redirect URI=[%s]",
			utils.TruncateSensitive(existingClient.ID),
			utils.SanitizeURL(redirectURI),
		)
		return errors.New(errors.ErrCodeInvalidRequest, "invalid redirect_uri")
	}

	return nil
}

// ValidateAndRetrieveClient validates the provided registration access token, ensures the client exists,
// revokes the token if necessary, and compares the token value to the clientID. It returns an error if any
// validation fails or if the client cannot be retrieved.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID: The ID of the client to validate and retrieve.
//   - registrationAccessToken: The access token used for validation.
//
// Returns:
//   - *CLientInformationResponse: If the the request is successful.
//   - error: An error if validation fails or the client cannot be retrieved.
func (cs *clientService) ValidateAndRetrieveClient(ctx context.Context, clientID, registrationAccessToken string) (*client.ClientInformationResponse, error) {
	requestID := utils.GetRequestID(ctx)
	if clientID == "" || registrationAccessToken == "" {
		cs.logger.Error(cs.module, requestID, "[ValidateAndRetrieveClient]: Failed to validate request: Missing required parameters.")
		return nil, errors.NewMissingParametersError()
	}

	retrievedClient, err := cs.validateClientAndToken(ctx, clientID, registrationAccessToken, constants.ClientRead)
	if err != nil {
		cs.logger.Error(cs.module, requestID, "[ValidateAndRetrieveClient]: Failed to validate client or registration access token: %v", err)
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
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client to validate and update.
//   - registrationAccessToken string: The access token used for validation.
//   - request *ClientUpdateRequest: The client update request.
//
// Returns:
//   - *CLientInformationResponse: If the the request is successful.
//   - error: An error if validation fails or the client cannot be updated.
func (cs *clientService) ValidateAndUpdateClient(ctx context.Context, clientID, registrationAccessToken string, request *client.ClientUpdateRequest) (*client.ClientInformationResponse, error) {
	requestID := utils.GetRequestID(ctx)
	if clientID == "" || registrationAccessToken == "" {
		err := errors.NewMissingParametersError()
		cs.logger.Error(cs.module, requestID, "[ValidateAndUpdateClient]: Failed to validate request: Missing required parameters")
		return nil, err
	}

	if request.ID != clientID {
		cs.logger.Error(cs.module, requestID, "[ValidateAndUpdateClient]: Provided client ID=[%s] does match with the registered clientID=[%s]",
			utils.TruncateSensitive(request.ID),
			utils.TruncateSensitive(clientID),
		)
		return nil, errors.New(errors.ErrCodeUnauthorized, "the provided client ID is invalid or does not match the registered credentials")
	}

	retrievedClient, err := cs.validateClientAndToken(ctx, clientID, registrationAccessToken, constants.ClientManage)
	if err != nil {
		cs.logger.Error(cs.module, requestID, "[ValidateAndUpdateClient]: Failed to validate client or registration access token: %v", err)
		return nil, err
	}

	if retrievedClient.IsConfidential() {
		request.Type = client.Confidential
		if err := request.Validate(); err != nil {
			cs.logger.Error(cs.module, requestID, "[ValidateAndUpdateClient]: Failed to validate ClientUpdateRequest: %v", err)
			return nil, err
		} else if request.Secret != "" && request.Secret != retrievedClient.Secret {
			cs.logger.Error(cs.module, requestID, "[ValidateAndUpdateClient]: The provided client secret=[%s] does not match with the registered client secret=[%s]",
				utils.TruncateSensitive(request.Secret),
				utils.TruncateSensitive(retrievedClient.Secret),
			)
			return nil, errors.New(errors.ErrCodeUnauthorized, "the provided client secret is invalid or does not match the registered credentials")
		}
	}

	retrievedClient.UpdateValues(request)
	if err := cs.clientRepo.UpdateClient(ctx, retrievedClient); err != nil {
		cs.logger.Error(cs.module, requestID, "[ValidateAndUpdateClient]: Failed to update client=[%s]: %v", utils.TruncateSensitive(retrievedClient.ID), err)
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

// ValidateAndDeleteClient validates the provided registration access token, ensures the client exists,
// revokes the token if necessary, and compares the token value to the clientID. It returns an error if
// any validation fails or the client cannot be deleted.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client to validate and delete.
//   - registrationAccessToken string: The access token used for validation.
//
// Returns:
//   - error: An error if validation fails or the client cannot be deleted.
func (cs *clientService) ValidateAndDeleteClient(ctx context.Context, clientID, registrationAccessToken string) error {
	requestID := utils.GetRequestID(ctx)
	if clientID == "" || registrationAccessToken == "" {
		err := errors.NewMissingParametersError()
		cs.logger.Error(cs.module, requestID, "[ValidateAndDeleteClient]: Failed to delete client: %v", err)
		return err
	}

	retrievedClient, err := cs.validateClientAndToken(ctx, clientID, registrationAccessToken, constants.ClientDelete)
	if err != nil {
		cs.logger.Error(cs.module, requestID, "[ValidateAndDeleteClient]: Failed to validate client or registration access token: %v", err)
		return err
	}

	if err := cs.clientRepo.DeleteClientByID(ctx, clientID); err != nil {
		cs.logger.Error(cs.module, requestID, "[ValidateAndDeleteClient]: Failed to delete client=[%s]: %v", utils.TruncateSensitive(clientID), err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to delete client")
	}

	if retrievedClient.IsConfidential() {
		registrationAccessToken, err = cs.tokenService.DecryptToken(ctx, registrationAccessToken)
		if err != nil {
			return err
		}
	}

	errChan := cs.tokenService.DeleteTokenAsync(ctx, registrationAccessToken)
	if err := <-errChan; err != nil {
		cs.logger.Error(cs.module, requestID, "[ValidateAndDeleteClient]: Failed to delete registration access token: %v", err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to delete registration access token")
	}

	return nil
}

// validateClientAuthorization checks if the client is authorized to perform certain actions
// based on its configuration, including its type, client secret, grant type, and scope.
// Note: If the client secret is not needed for validation, it can be passed as an empty string.
// Note: If the grant type is not needed for validation, it can be passed as an empty string.
//
// Parameters:
//   - existingClient *Client: The client whose authorization is being validated.
//   - clientSecret string: The client secret to validate against the stored value.
//   - scope string: The client scope(s) to validate against the stored value.
//   - grantType string: The client grant type to validate against the stored value.
//
// Returns:
//   - error: An error indicating why the client is not authorized, or nil if the client is valid.
func (cs *clientService) validateClientAuthorization(existingClient *client.Client, clientSecret string, requestedGrant string, requestedScopes string) error {
	if clientSecret != "" {
		if !existingClient.IsConfidential() {
			return errors.New(errors.ErrCodeUnauthorizedClient, "client is not confidential")
		}
		if !existingClient.SecretsMatch(clientSecret) {
			return errors.New(errors.ErrCodeInvalidClient, "the client credentials are invalid or incorrectly formatted")
		}
	}

	scopesArr := strings.Split(requestedScopes, " ")
	for _, scope := range scopesArr {
		if !existingClient.HasScope(scope) {
			return errors.New(errors.ErrCodeInsufficientScope, "client does not have the required scope(s)")
		}
	}

	if requestedGrant != "" && !existingClient.HasGrantType(requestedGrant) {
		return errors.New(errors.ErrCodeUnauthorizedClient, "client does not have the required grant type")
	}

	return nil
}

func (cs *clientService) validateClientAndToken(ctx context.Context, clientID, registrationAccessToken, scope string) (*client.Client, error) {
	retrievedClient, err := cs.GetClientByID(ctx, clientID)
	if retrievedClient == nil {
		return nil, cs.revokeTokenAndReturnError(ctx, registrationAccessToken, errors.ErrCodeUnauthorized, "the provided client ID is invalid or does not match the registered credentials")
	}

	if retrievedClient.IsConfidential() {
		registrationAccessToken, err = cs.tokenService.DecryptToken(ctx, registrationAccessToken)
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		cs.logger.Error(cs.module, "", "An error occurred retrieving the client by ID: %v", err)
		return nil, cs.revokeTokenAndReturnError(ctx, registrationAccessToken, errors.ErrCodeInternalServerError, "an internal error occurred")
	} else if !retrievedClient.HasScope(scope) && !retrievedClient.HasScope(constants.ClientManage) {
		return nil, cs.revokeTokenAndReturnError(ctx, registrationAccessToken, errors.ErrCodeInsufficientScope, "client does not have the required scopes for this request")
	}

	tokenClaim, err := cs.tokenService.ParseAndValidateToken(ctx, registrationAccessToken)
	if err != nil {
		return nil, cs.revokeTokenAndReturnError(ctx, registrationAccessToken, errors.ErrCodeInvalidToken, "failed to parse registration access token")
	} else if tokenClaim.Subject != clientID {
		return nil, cs.revokeTokenAndReturnError(ctx, registrationAccessToken, errors.ErrCodeUnauthorized, "the registration access token subject does not match with the client ID in the request")
	} else if time.Now().Unix() > tokenClaim.ExpiresAt {
		return nil, cs.revokeTokenAndReturnError(ctx, registrationAccessToken, errors.ErrCodeUnauthorized, "the registration access token has expired")
	}

	return retrievedClient, nil
}

func (cs *clientService) generateUniqueClientID(ctx context.Context) (string, error) {
	const maxRetries = 5
	const retryDelay = 100 * time.Millisecond

	for range maxRetries {
		clientID := crypto.GenerateUUID()
		if !cs.clientRepo.IsExistingID(ctx, clientID) {
			return clientID, nil
		}

		time.Sleep(retryDelay)
	}

	return "", errors.New(errors.ErrCodeInternalServerError, "failed to generate a unique client ID after multiple retries")
}

func (cs *clientService) generateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", errors.NewInternalServerError()
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func (cs *clientService) isValidURIFormat(uri string, clientType string) (bool, error) {
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

func (cs *clientService) parseURI(uri string) (*url.URL, error) {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInvalidRedirectURI, "invalid redirect URI format")
	}

	if parsedURL.Fragment != "" {
		return nil, errors.New(errors.ErrCodeInvalidRedirectURI, "fragments are not allowed in the redirect URI")
	}

	return parsedURL, nil
}

func (cs *clientService) validateRedirectURIScheme(parsedURL *url.URL) error {
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" && !strings.HasPrefix(parsedURL.Scheme, "custom") {
		return errors.New(
			errors.ErrCodeInvalidRedirectURI, "invalid scheme, must be 'https' or 'http' for localhost or 'custom' for mobile",
		)
	}

	return nil
}

func (cs *clientService) validatePublicClientURIScheme(parsedURL *url.URL) error {
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

func (cs *clientService) validateConfidentialClientURIScheme(parsedURL *url.URL) error {
	if strings.Contains(parsedURL.Host, "*") {
		return errors.New(errors.ErrCodeInvalidRedirectURI, "wildcards are not allowed for confidential clients")
	}

	return nil
}

func (cs *clientService) revokeTokenAndReturnError(ctx context.Context, token, errorCode, errorMessage string) error {
	if err := cs.tokenService.DeleteToken(ctx, token); err != nil {
		return errors.New(errors.ErrCodeInternalServerError, "failed to revoke registration access token")
	}
	return errors.New(errorCode, errorMessage)
}

func (cs *clientService) buildClientConfigurationEndpoint(clientID string) string {
	URL := config.GetServerConfig().URL()
	return fmt.Sprintf("%s%s/%s", URL, web.ClientEndpoints.ClientConfiguration, clientID)
}
