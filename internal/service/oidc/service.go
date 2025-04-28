package service

import (
	"context"
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/constants"
	authz "github.com/vigiloauth/vigilo/internal/domain/authorization"
	jwks "github.com/vigiloauth/vigilo/internal/domain/jwks"
	oidc "github.com/vigiloauth/vigilo/internal/domain/oidc"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
)

var _ oidc.OIDCService = (*oidcService)(nil)

type oidcService struct {
	authorizationService authz.AuthorizationService

	logger *config.Logger
	module string
}

func NewOIDCService(authorizationService authz.AuthorizationService) oidc.OIDCService {
	return &oidcService{
		authorizationService: authorizationService,
		logger:               config.GetServerConfig().Logger(),
		module:               "OIDC Service",
	}
}

// GetUserInfo retrieves the user's profile information based on the claims
// extracted from a validated access token.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - accessTokenClaims *TokenClaims: A pointer to TokenClaims that were parsed and validated
//     from the access token. These typically include standard OIDC claims such as
//     'sub' (subject identifier), 'scope', 'exp' (expiration), etc.
//   - r *http.Request: The HTTP request containing the cookies.

// Returns:
//   - *UserInfoResponse: A pointer to a UserInfoResponse struct containing the requested user
//     information (e.g., name, email, profile picture), filtered according to the
//     authorized scopes.
//   - error: An error if the user cannot be found, the scopes are insufficient, or any
//     other issue occurs during retrieval.
func (o *oidcService) GetUserInfo(ctx context.Context, accessTokenClaims *token.TokenClaims, r *http.Request) (*user.UserInfoResponse, error) {
	requestID := utils.GetRequestID(ctx)

	retrievedUser, err := o.authorizationService.AuthorizeUserInfoRequest(ctx, accessTokenClaims, r)
	if err != nil {
		o.logger.Error(o.module, requestID, "[GetUserInfo]: Failed to authorize user info request: %v", err)
		wrappedErr := errors.Wrap(err, "", "failed to authorize request")
		return nil, wrappedErr
	}

	userInfoResponse := &user.UserInfoResponse{Sub: retrievedUser.ID}
	requestedScopes := strings.Split(accessTokenClaims.Scopes, " ")
	o.populateUserInfoFromScopes(userInfoResponse, retrievedUser, requestedScopes)

	return userInfoResponse, nil
}

// GetJwks retrieves the JSON Web Key Set (JWKS) used for verifying signatures
// of tokens issued by the OpenID Connect provider.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//
// Returns:
//   - *Jwks: A pointer to a Jwks struct containing the public keys in JWKS format.
func (o *oidcService) GetJwks(ctx context.Context) *jwks.Jwks {
	tokenConfig := config.GetServerConfig().TokenConfig()
	publicKey := tokenConfig.PublicKey()
	keyID := tokenConfig.KeyID()
	return &jwks.Jwks{
		Keys: []jwks.JWK{
			jwks.NewJWK(keyID, publicKey),
		},
	}
}

func (o *oidcService) populateUserInfoFromScopes(
	userInfoResponse *user.UserInfoResponse,
	retrievedUser *user.User,
	requestedScopes []string,
) {
	for _, scope := range requestedScopes {
		switch scope {
		case constants.UserProfile:
			userInfoResponse.Name = retrievedUser.FullName
			userInfoResponse.Username = retrievedUser.Username
			userInfoResponse.Birthdate = retrievedUser.Birthdate
			userInfoResponse.FirstName = retrievedUser.FirstName
			userInfoResponse.MiddleName = retrievedUser.MiddleName
			userInfoResponse.FamilyName = retrievedUser.FamilyName
			userInfoResponse.UpdatedAt = retrievedUser.UpdatedAt.UTC()
		case constants.UserEmail:
			userInfoResponse.Email = retrievedUser.Email
			userInfoResponse.EmailVerified = retrievedUser.EmailVerified
		case constants.UserPhone:
			userInfoResponse.PhoneNumber = retrievedUser.PhoneNumber
			userInfoResponse.PhoneNumberVerified = retrievedUser.PhoneNumberVerified
		case constants.UserAddress:
			userInfoResponse.Address = retrievedUser.Address
		}
	}
}
