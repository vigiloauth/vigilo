package domain

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	"github.com/vigiloauth/vigilo/v2/internal/types"
)

const validCodeChallenge string = "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_"

func TestClientRegistrationRequest_Validate(t *testing.T) {
	t.Run("Successful Validation", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.Scopes = []types.Scope{}
		err := client.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid Grant Types", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.ApplicationType = constants.NativeApplicationType
		client.TokenEndpointAuthMethod = types.NoTokenAuth
		client.GrantTypes = append(client.GrantTypes, constants.ClientCredentialsGrantType)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Redirect URIS", func(t *testing.T) {
		invalidRedirectURI := "http:/missing-slash/callback"
		client := createClientRegistrationRequest()
		client.RedirectURIs = append(client.RedirectURIs, invalidRedirectURI)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Scopes", func(t *testing.T) {
		invalidScope := "update"
		client := createClientRegistrationRequest()
		client.Scopes = append(client.Scopes, types.Scope(invalidScope))

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Response Types", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.ResponseTypes = []string{constants.TokenResponseType}

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid JWKS URI", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.JwksURI = "http/invalid.org/public_keys.jwks"

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Logo URI", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.LogoURI = "http/invalid.org/logo.png"

		err := client.Validate()
		assert.Error(t, err)
	})
}

func TestClientUpdateRequest_Validate(t *testing.T) {
	t.Run("Successful Validation", func(t *testing.T) {
		client := createClientUpdateRequest()
		err := client.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid Grant Types", func(t *testing.T) {
		client := createClientUpdateRequest()
		client.GrantTypes = append(client.GrantTypes, constants.ClientCredentialsGrantType)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Redirect URIS", func(t *testing.T) {
		invalidRedirectURI := "http:/missing-slash/callback"
		client := createClientUpdateRequest()
		client.RedirectURIs = append(client.RedirectURIs, invalidRedirectURI)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Scopes", func(t *testing.T) {
		invalidScope := "update"
		client := createClientUpdateRequest()
		client.Scopes = append(client.Scopes, types.Scope(invalidScope))

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Response Types", func(t *testing.T) {
		client := createClientUpdateRequest()
		client.ResponseTypes = []string{constants.TokenResponseType}

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid JWKS URI", func(t *testing.T) {
		client := createClientUpdateRequest()
		client.JwksURI = "http/invalid.org/public_keys.jwks"

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Logo URI", func(t *testing.T) {
		client := createClientUpdateRequest()
		client.LogoURI = "http/invalid.org/logo.png"

		err := client.Validate()
		assert.Error(t, err)
	})
}

func TestClientAuthorizationRequest_Validate(t *testing.T) {
	t.Run("Validation successful", func(t *testing.T) {
		tests := []struct {
			name    string
			request *ClientAuthorizationRequest
		}{
			{
				name: "Valid Base64 URL-encoded string (43-44 chars)",
				request: &ClientAuthorizationRequest{
					Client:              createClient(),
					ResponseType:        constants.CodeResponseType,
					CodeChallenge:       "abcdEFGHijklMNOPqrstUVWasdasd2dasXyz0123456789-_",
					CodeChallengeMethod: types.SHA256CodeChallengeMethod,
				},
			},
			{
				name: "Valid long Base64 URL-encoded string (greater than 44 chars)",
				request: &ClientAuthorizationRequest{
					Client:              createClient(),
					ResponseType:        constants.CodeResponseType,
					CodeChallenge:       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
					CodeChallengeMethod: types.SHA256CodeChallengeMethod,
				},
			},
		}

		for _, test := range tests {
			err := ValidateClientAuthorizationRequest(test.request)
			assert.NoError(t, err, fmt.Sprintf("expected no error for %s", test.name))
		}
	})

	t.Run("Error is returned when the code challenge contains invalid characters", func(t *testing.T) {
		tests := []struct {
			name    string
			request *ClientAuthorizationRequest
		}{
			{
				name: "Code challenge contains invalid characters (+, /)",
				request: &ClientAuthorizationRequest{
					Client:              createClient(),
					ResponseType:        constants.CodeResponseType,
					CodeChallenge:       "abcdEFGHijklMNOPqrstUVWXyz01234562345654323456789+/",
					CodeChallengeMethod: types.SHA256CodeChallengeMethod,
				},
			},
			{
				name: "Code challenge contains invalid characters (@, #, !)",
				request: &ClientAuthorizationRequest{
					Client:              createClient(),
					ResponseType:        constants.CodeResponseType,
					CodeChallenge:       "abcdEFGHijklMNOPqrstUVWXyz012345012345678765434567887656789@#!",
					CodeChallengeMethod: types.SHA256CodeChallengeMethod,
				},
			},
		}

		for _, test := range tests {
			err := ValidateClientAuthorizationRequest(test.request)
			assert.Error(t, err, fmt.Sprintf("expected error for %s", test.name))
			expectedMessage := "invalid characters: only A-Z, a-z, 0-9, '-', and '_' are allowed (Base64 URL encoding)"
			assert.Contains(t, expectedMessage, err.Error())
		}
	})

	t.Run("Error is returned when the code challenge is too short", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			CodeChallenge:       "short",
			CodeChallengeMethod: types.SHA256CodeChallengeMethod,
			Client:              createClient(),
			ResponseType:        constants.CodeResponseType,
		}

		err := ValidateClientAuthorizationRequest(request)
		expectedErr := fmt.Sprintf("invalid code challenge length (%d): must be between 43 and 128 characters", len(request.CodeChallenge))

		assert.Error(t, err, "expected an error when code challenge is too short")
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Error is returned when the code challenge method is invalid", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			CodeChallenge:       validCodeChallenge,
			CodeChallengeMethod: "invalid",
			Client:              createClient(),
			ResponseType:        constants.CodeResponseType,
		}

		err := ValidateClientAuthorizationRequest(request)
		expectedErr := "invalid code challenge method: 'invalid'. Valid methods are 'plain' and 'SHA-256'"

		assert.Error(t, err, "expected an error when code challenge method is not plain or SHA-256")
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Code challenge method defaults to plain if not present", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			Client:        createClient(),
			ResponseType:  constants.CodeResponseType,
			CodeChallenge: validCodeChallenge,
		}

		err := ValidateClientAuthorizationRequest(request)
		assert.NoError(t, err)
		assert.Equal(t, types.PlainCodeChallengeMethod, request.CodeChallengeMethod)
	})

	t.Run("Error is returned when client does not have 'code' response type", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			ResponseType: constants.IDTokenResponseType,
			Client: &Client{
				Type:          types.PublicClient,
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
				ResponseTypes: []string{constants.IDTokenResponseType},
				RequiresPKCE:  true,
			},
			CodeChallenge: validCodeChallenge,
		}

		err := ValidateClientAuthorizationRequest(request)
		expectedError := "code response type is required to receive an authorization code"

		assert.Error(t, err)
		assert.Contains(t, expectedError, err.Error())
	})

	t.Run("Success when request does not have PKCE grant and no code challenge is passed", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			ResponseType: constants.CodeResponseType,
			Client: &Client{
				Type:          types.ConfidentialClient,
				ResponseTypes: []string{constants.CodeResponseType},
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
			},
		}

		err := ValidateClientAuthorizationRequest(request)
		assert.NoError(t, err)
	})

	t.Run("Error is returned when the client does not have authorization code grant", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			Client: &Client{
				Type:          types.PublicClient,
				ResponseTypes: []string{constants.CodeResponseType},
			},
			ResponseType:        constants.CodeResponseType,
			CodeChallengeMethod: types.PlainCodeChallengeMethod,
		}

		err := ValidateClientAuthorizationRequest(request)
		expectedErr := "authorization code grant is required for this request"

		assert.Error(t, err)
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Error is returned when public client does not have PKCE grant", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			Client: &Client{
				Type:          types.PublicClient,
				ResponseTypes: []string{constants.CodeResponseType},
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
			},
			ResponseType:        constants.CodeResponseType,
			CodeChallenge:       validCodeChallenge,
			CodeChallengeMethod: types.PlainCodeChallengeMethod,
		}

		err := ValidateClientAuthorizationRequest(request)
		expectedErr := "PKCE is required when providing a code challenge"

		assert.Error(t, err)
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Error is returned when client has PKCE but does not provide a code challenge", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			Client: &Client{
				Type:          types.PublicClient,
				ResponseTypes: []string{constants.CodeResponseType},
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
				RequiresPKCE:  true,
			},
			ResponseType: constants.CodeResponseType,
		}

		err := ValidateClientAuthorizationRequest(request)
		expectedErr := "code_challenge is required for PKCE"

		assert.Error(t, err)
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Success when confidential client is not using PKCE", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			Client: &Client{
				Type:          types.ConfidentialClient,
				ResponseTypes: []string{constants.CodeResponseType},
				GrantTypes:    []string{constants.AuthorizationCodeGrantType},
			},
			ResponseType: constants.CodeResponseType,
		}

		err := ValidateClientAuthorizationRequest(request)
		assert.NoError(t, err)
	})
}

func createClientRegistrationRequest() *ClientRegistrationRequest {
	return &ClientRegistrationRequest{
		Name:                    "Test Client",
		Type:                    types.PublicClient,
		RedirectURIs:            []string{"https://www.example-app.com/callback"},
		GrantTypes:              []string{constants.AuthorizationCodeGrantType},
		RequiresPKCE:            true,
		Scopes:                  []types.Scope{types.OpenIDScope, types.TokenIntrospectScope},
		ResponseTypes:           []string{constants.CodeResponseType, constants.IDTokenResponseType},
		ApplicationType:         constants.WebApplicationType,
		TokenEndpointAuthMethod: types.ClientSecretBasicTokenAuth,
	}
}

func createClientUpdateRequest() *ClientUpdateRequest {
	return &ClientUpdateRequest{
		Name:          "Test Client",
		Type:          types.PublicClient,
		RedirectURIs:  []string{"https://www.example-app.com/callback", "myapp://callback"},
		GrantTypes:    []string{constants.AuthorizationCodeGrantType},
		Scopes:        []types.Scope{types.OpenIDScope, types.TokenIntrospectScope},
		ResponseTypes: []string{constants.CodeResponseType, constants.IDTokenResponseType},
	}
}

func createClient() *Client {
	return &Client{
		Name:          "Test Client",
		Type:          types.PublicClient,
		RedirectURIs:  []string{"https://www.example-app.com/callback", "myapp://callback"},
		GrantTypes:    []string{constants.AuthorizationCodeGrantType},
		RequiresPKCE:  true,
		Scopes:        []types.Scope{types.OpenIDScope},
		ResponseTypes: []string{constants.CodeResponseType, constants.IDTokenResponseType},
	}
}
