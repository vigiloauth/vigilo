package service

import (
	"context"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authorization"
	jwks "github.com/vigiloauth/vigilo/v2/internal/domain/jwks"
	oidc "github.com/vigiloauth/vigilo/v2/internal/domain/oidc"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
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
//
// Returns:
//   - *UserInfoResponse: A pointer to a UserInfoResponse struct containing the requested user
//     information (e.g., name, email, profile picture), filtered according to the
//     authorized scopes.
//   - error: An error if the user cannot be found, the scopes are insufficient, or any
//     other issue occurs during retrieval.
func (s *oidcService) GetUserInfo(ctx context.Context, accessTokenClaims *token.TokenClaims) (*user.UserInfoResponse, error) {
	requestID := utils.GetRequestID(ctx)

	retrievedUser, err := s.authorizationService.AuthorizeUserInfoRequest(ctx, accessTokenClaims)
	if err != nil {
		s.logger.Error(s.module, requestID, "[GetUserInfo]: Failed to authorize user info request: %v", err)
		wrappedErr := errors.Wrap(err, "", "failed to authorize request")
		return nil, wrappedErr
	}

	userInfoResponse := &user.UserInfoResponse{Sub: retrievedUser.ID}
	requestedScopes := types.ParseScopesString(accessTokenClaims.Scopes.String())
	s.populateUserInfoFromScopes(userInfoResponse, retrievedUser, requestedScopes)

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
func (s *oidcService) GetJwks(ctx context.Context) *jwks.Jwks {
	tokenConfig := config.GetServerConfig().TokenConfig()
	publicKey := tokenConfig.PublicKey()
	keyID := tokenConfig.KeyID()
	return &jwks.Jwks{
		Keys: []jwks.JWK{
			jwks.NewJWK(keyID, publicKey),
		},
	}
}

func (s *oidcService) populateUserInfoFromScopes(
	userInfoResponse *user.UserInfoResponse,
	retrievedUser *user.User,
	requestedScopes []types.Scope,
) {
	for _, scope := range requestedScopes {
		switch scope {
		case types.UserProfileScope:
			userInfoResponse.Name = retrievedUser.Name
			userInfoResponse.FamilyName = retrievedUser.FamilyName
			userInfoResponse.GivenName = retrievedUser.GivenName
			userInfoResponse.MiddleName = retrievedUser.MiddleName
			userInfoResponse.Nickname = retrievedUser.Nickname
			userInfoResponse.PreferredUsername = retrievedUser.PreferredUsername
			userInfoResponse.Profile = retrievedUser.Profile
			userInfoResponse.Picture = retrievedUser.Picture
			userInfoResponse.Website = retrievedUser.Website
			userInfoResponse.Gender = retrievedUser.Gender
			userInfoResponse.Birthdate = retrievedUser.Birthdate
			userInfoResponse.Zoneinfo = retrievedUser.Zoneinfo
			userInfoResponse.Locale = retrievedUser.Locale
			userInfoResponse.UpdatedAt = retrievedUser.UpdatedAt.UTC().Unix()
		case types.UserEmailScope:
			userInfoResponse.Email = retrievedUser.Email
			userInfoResponse.EmailVerified = &retrievedUser.EmailVerified
		case types.UserPhoneScope:
			userInfoResponse.PhoneNumber = retrievedUser.PhoneNumber
			userInfoResponse.PhoneNumberVerified = &retrievedUser.PhoneNumberVerified
		case types.UserAddressScope:
			userInfoResponse.Address = retrievedUser.Address
		}
	}
}
