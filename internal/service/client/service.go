package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/internal/crypto"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// Ensures that ClientServiceImpl implements the ClientService interface.
var _ client.ClientService = (*ClientServiceImpl)(nil)

// ClientServiceImpl provides the implementation of ClientService.
type ClientServiceImpl struct {
	clientRepo client.ClientRepository
}

// NewClientService creates a new instance of ClientServiceImpl.
//
// Parameters:
//
//	clientRepo ClientRepository: The client store to be used.
//
// Returns:
//
//	*ClientServiceImpl: A new instance of ClientServiceImpl.
func NewClientService(clientRepo client.ClientRepository) *ClientServiceImpl {
	return &ClientServiceImpl{clientRepo: clientRepo}
}

// SaveClient registers a new public client.
//
// Parameters:
//
//	newClient *client.Client: The client to be registered.
//
// Returns:
//
//	*client.ClientRegistrationResponse: The response containing client details.
//	error: An error if registration fails.
func (cs *ClientServiceImpl) SaveClient(newClient *client.Client) (*client.ClientRegistrationResponse, error) {
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
	}

	newClient.CreatedAt, newClient.UpdatedAt = time.Now(), time.Now()
	if err := cs.clientRepo.SaveClient(newClient); err != nil {
		return nil, errors.Wrap(err, "", "failed to create new client")
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
	if !retrievedClient.HasScope(client.ClientManage) {
		return nil, errors.New(errors.ErrCodeInvalidScope, "client does not have required scope 'client:manage'")
	}
	if !retrievedClient.IsConfidential() {
		return nil, errors.New(errors.ErrCodeUnauthorizedClient, "client is not type 'confidential'")
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
	if !existingClient.IsConfidential() {
		return nil, errors.New(errors.ErrCodeUnauthorizedClient, "client is not type 'confidential'")
	}
	if existingClient.Secret != clientSecret {
		return nil, errors.New(errors.ErrCodeInvalidClient, "invalid 'client_secret' provided")
	}

	if !existingClient.HasGrantType(client.ClientCredentials) {
		return nil, errors.New(errors.ErrCodeInvalidGrant, "client does not have required grant type 'client_credentials'")
	}

	if !existingClient.HasScope(client.ClientManage) {
		return nil, errors.New(errors.ErrCodeInvalidScope, "client does not have required scope 'client:manage'")
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

// generateUniqueClientID generates a unique client ID, ensuring it is not already in use.
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
		if existingClient := cs.clientRepo.GetClientByID(clientID); existingClient == nil {
			return clientID, nil
		}
		time.Sleep(retryDelay)
	}

	return "", errors.NewInternalServerError()
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
func (cs *ClientServiceImpl) isValidURIFormat(uri string, clientType client.ClientType) (bool, error) {
	parsedURL, err := url.Parse(uri)
	if err != nil {
		return false, errors.New(errors.ErrCodeInvalidFormat, "invalid redirect URI format")
	}

	if parsedURL.Scheme != "https" &&
		parsedURL.Scheme != "http" &&
		!strings.HasPrefix(parsedURL.Scheme, "custom") {
		return false, errors.New(
			errors.ErrCodeInvalidRedirectURI,
			"invalid scheme, must be 'https' or 'http' for localhost or 'custom' for mobile",
		)
	}

	if clientType == client.Public {
		if parsedURL.Scheme == "http" && parsedURL.Host != "localhost" {
			return false, errors.New(errors.ErrCodeInvalidRedirectURI, "'http' scheme is only allowed for 'localhost'")
		}
		if parsedURL.Scheme == "https" && parsedURL.Host == "localhost" {
			return false, errors.New(
				errors.ErrCodeInvalidRedirectURI,
				"'https' scheme is not allowed for for public clients using 'localhost'",
			)
		}
	} else if clientType == client.Confidential {
		if strings.Contains(parsedURL.Host, "*") {
			return false, errors.New(errors.ErrCodeInvalidRedirectURI, "wildcards are not allowed for confidential clients")
		}
	} else {
		return false, errors.New(errors.ErrCodeInvalidClient, fmt.Sprintf("invalid client_type: %s", clientType.String()))
	}

	if parsedURL.Fragment != "" {
		return false, errors.New(errors.ErrCodeInvalidRedirectURI, "fragments are not allowed in the redirectURI")
	}

	return true, nil
}
