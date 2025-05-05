package domain

import (
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

// DiscoveryJSON represents the OpenID Connect Discovery Document.
// This document provides metadata about the OpenID Provider (OP),
// including supported endpoints, scopes, grant types, and algorithms.
type DiscoveryJSON struct {
	Issuer                string `json:"issuer"`                 // The URL of the OpenID Provider (OP).
	AuthorizationEndpoint string `json:"authorization_endpoint"` // The endpoint for authorization requests.
	TokenEndpoint         string `json:"token_endpoint"`         // The endpoint for token requests.
	UserInfoEndpoint      string `json:"userinfo_endpoint"`      // The endpoint for retrieving user information.
	JwksURI               string `json:"jwks_uri"`               // The URL for the JSON Web Key Set (JWKS).
	RegistrationEndpoint  string `json:"registration_endpoint"`  // The endpoint for client registration.

	SupportedScopes                   []string `json:"scopes_supported"`                         // List of supported scopes.
	SupportedResponseTypes            []string `json:"response_types_supported"`                 // List of supported response types.
	SupportedGrantTypes               []string `json:"grant_types_supported"`                    // List of supported grant types.
	SupportedSubjectTypes             []string `json:"subject_types_supported"`                  // List of supported subject types (e.g., "public").
	SupportedIDTokenSigningAlg        []string `json:"id_token_signing_alg_values_supported"`    // List of supported algorithms for ID token signing.
	SupportedIDTokenEncryptionAlg     []string `json:"id_token_encryption_alg_values_supported"` // List of supported algorithms for ID token encryption.
	SupportedTokenEndpointAuthMethods []string `json:"token_endpoint_auth_methods_supported"`    // List of supported token endpoint authentication methods.
}

// NewDiscoveryJSON creates a new instance of DiscoveryJSON with the provided base URL.
// It populates the discovery document with metadata about the OpenID Provider.
//
// Parameters:
//   - baseURL: The base URL of the OpenID Provider.
//
// Returns:
//   - *DiscoveryJSON: A populated DiscoveryJSON instance.
func NewDiscoveryJSON(baseURL string) *DiscoveryJSON {
	return &DiscoveryJSON{
		Issuer:                        baseURL + "/oauth2",
		AuthorizationEndpoint:         baseURL + web.OAuthEndpoints.Authorize,
		TokenEndpoint:                 baseURL + web.OAuthEndpoints.Token,
		UserInfoEndpoint:              baseURL + web.OIDCEndpoints.UserInfo,
		JwksURI:                       baseURL + web.OIDCEndpoints.JWKS,
		RegistrationEndpoint:          baseURL + web.ClientEndpoints.Register,
		SupportedScopes:               utils.KeysToSlice(constants.SupportedScopes),
		SupportedResponseTypes:        utils.KeysToSlice(constants.SupportedResponseTypes),
		SupportedGrantTypes:           utils.KeysToSlice(constants.SupportedGrantTypes),
		SupportedSubjectTypes:         []string{constants.SubjectTypePublic},
		SupportedIDTokenSigningAlg:    []string{constants.IDTokenSigningAlgorithmRS256},
		SupportedIDTokenEncryptionAlg: []string{constants.IDTokenEncryptionAlgorithmRSA},
		SupportedTokenEndpointAuthMethods: []string{
			constants.AuthMethodClientSecretBasic,
			constants.AuthMethodClientSecretPost,
			constants.AuthMethodNone,
		},
	}
}
