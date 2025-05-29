package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"

	clients "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	encryption "github.com/vigiloauth/vigilo/v2/internal/domain/crypto"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

var _ clients.ClientCreator = (*clientCreator)(nil)

type clientCreator struct {
	repo       clients.ClientRepository
	validator  clients.ClientValidator
	issuer     tokens.TokenIssuer
	encryption encryption.Cryptographer

	logger *config.Logger
	module string
}

func NewClientCreator(
	repo clients.ClientRepository,
	validator clients.ClientValidator,
	issuer tokens.TokenIssuer,
	encryption encryption.Cryptographer,
) clients.ClientCreator {
	return &clientCreator{
		repo:       repo,
		validator:  validator,
		issuer:     issuer,
		encryption: encryption,
		logger:     config.GetServerConfig().Logger(),
		module:     "Client Creator",
	}
}

func (c *clientCreator) Register(
	ctx context.Context,
	req *clients.ClientRegistrationRequest,
) (*clients.ClientRegistrationResponse, error) {
	requestID := utils.GetRequestID(ctx)

	if err := c.validator.ValidateRegistrationRequest(ctx, req); err != nil {
		c.logger.Error(c.module, requestID, "[Register]: Failed to validate client")
		return nil, errors.Wrap(err, "", "failed to validate client")
	}

	client := clients.NewClientFromRegistrationRequest(req)
	client.ID = constants.ClientIDPrefix + utils.GenerateUUID()
	if client.Type == types.ConfidentialClient {
		if err := c.generateClientSecret(requestID, client); err != nil {
			c.logger.Error(c.module, requestID, "[Register]: Failed to generate client secret: %v", err)
			return nil, errors.Wrap(err, "", "failed to generate secret")
		}
	}

	requestedScopes := types.CombineScopes(client.Scopes...)
	registrationAccessToken, err := c.issuer.IssueAccessToken(
		ctx,
		client.ID, "",
		requestedScopes, "", "",
	)

	if err != nil {
		c.logger.Error(c.module, requestID, "[RegisterClient]: Failed to generate registration access token: %v", err)
		return nil, errors.Wrap(err, "", "failed to generate the registration access token")
	}

	client.CreatedAt, client.UpdatedAt, client.IDIssuedAt = time.Now(), time.Now(), time.Now()
	client.RegistrationClientURI = c.buildClientConfigurationEndpoint(client.ID)
	client.RegistrationAccessToken = registrationAccessToken

	if err := c.repo.SaveClient(ctx, client); err != nil {
		c.logger.Error(c.module, requestID, "[RegisterClient]: Failed to save client: %v", err)
		return nil, errors.Wrap(err, "", "failed to register client")
	}

	return clients.NewClientRegistrationResponseFromClient(client), nil
}

func (c *clientCreator) generateClientSecret(requestID string, client *clients.Client) error {
	const clientSecretLength int = 32
	plainSecret, err := c.encryption.GenerateRandomString(clientSecretLength)
	if err != nil {
		c.logger.Error(c.module, requestID, "[Register]: Failed to generate client secret: %v", err)
		return errors.New(errors.ErrCodeRandomGenerationFailed, "failed to generate client secret")
	}

	hashedSecret, err := c.encryption.HashString(plainSecret)
	if err != nil {
		c.logger.Error(c.module, requestID, "[Register]: Failed to encrypt client secret: %v", err)
		return errors.New(errors.ErrCodeHashingFailed, "failed to hash client secret")
	}

	client.Secret = hashedSecret
	client.SecretExpiration = 0
	return nil
}

func (c *clientCreator) buildClientConfigurationEndpoint(clientID string) string {
	URL := config.GetServerConfig().URL()
	return fmt.Sprintf("%s%s/%s", URL, web.ClientEndpoints.ClientConfiguration, clientID)
}
