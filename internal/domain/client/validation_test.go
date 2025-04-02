package domain

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientRegistrationRequest_Validate(t *testing.T) {
	t.Run("Successful Validation", func(t *testing.T) {
		client := createClientRegistrationRequest()
		err := client.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid Client Type", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.Type = Confidential

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Grant Types", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.GrantTypes = append(client.GrantTypes, ClientCredentials)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Redirect URIS", func(t *testing.T) {
		invalidRedirectURI := "http:/missing-slash/callback"
		client := createClientRegistrationRequest()
		client.RedirectURIS = append(client.RedirectURIS, invalidRedirectURI)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Scopes", func(t *testing.T) {
		invalidScope := "update"
		client := createClientRegistrationRequest()
		client.Scopes = append(client.Scopes, invalidScope)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Response Types", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.ResponseTypes = []string{TokenResponseType}

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

	t.Run("Empty scopes is replaced with 'client:read'", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.Scopes = []string{}

		err := client.Validate()
		assert.NoError(t, err)
		assert.Equal(t, ClientRead, client.Scopes[0])
	})

	t.Run("Return error when public client is not using PKCE", func(t *testing.T) {
		client := createClientRegistrationRequest()
		client.GrantTypes = []string{AuthorizationCode}

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
		client.GrantTypes = append(client.GrantTypes, ClientCredentials)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Redirect URIS", func(t *testing.T) {
		invalidRedirectURI := "http:/missing-slash/callback"
		client := createClientUpdateRequest()
		client.RedirectURIS = append(client.RedirectURIS, invalidRedirectURI)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Scopes", func(t *testing.T) {
		invalidScope := "update"
		client := createClientUpdateRequest()
		client.Scopes = append(client.Scopes, invalidScope)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Response Types", func(t *testing.T) {
		client := createClientUpdateRequest()
		client.ResponseTypes = []string{TokenResponseType}

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
					CodeChallenge:       "abcdEFGHijklMNOPqrstUVWasdasd2dasXyz0123456789-_",
					CodeChallengeMethod: S256,
				},
			},
			{
				name: "Valid long Base64 URL-encoded string (greater than 44 chars)",
				request: &ClientAuthorizationRequest{
					CodeChallenge:       "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
					CodeChallengeMethod: S256,
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
					CodeChallenge:       "abcdEFGHijklMNOPqrstUVWXyz01234562345654323456789+/",
					CodeChallengeMethod: S256,
				},
			},
			{
				name: "Code challenge contains invalid characters (@, #, !)",
				request: &ClientAuthorizationRequest{
					CodeChallenge:       "abcdEFGHijklMNOPqrstUVWXyz012345012345678765434567887656789@#!",
					CodeChallengeMethod: S256,
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
			CodeChallengeMethod: S256,
		}

		err := ValidateClientAuthorizationRequest(request)
		expectedErr := fmt.Sprintf("invalid code challenge length (%d): must be between 43 and 128 characters", len(request.CodeChallenge))

		assert.Error(t, err, "expected an error when code challenge is too short")
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Error is returned when the code challenge method is invalid", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			CodeChallenge:       "this-is-a-plain-test-code-challenge",
			CodeChallengeMethod: "invalid",
		}

		err := ValidateClientAuthorizationRequest(request)
		expectedErr := "invalid code challenge method: 'invalid'. Valid methods are 'plain' and 'SHA-256'"

		assert.Error(t, err, "expected an error when code challenge method is not plain or SHA-256")
		assert.Contains(t, expectedErr, err.Error())
	})

	t.Run("Code challenge method defaults to plain if not present", func(t *testing.T) {
		request := &ClientAuthorizationRequest{
			CodeChallenge: "abcdEFGHijklMNOPqrstUVWX32343423142342423423423yz0123456789-_",
		}

		err := ValidateClientAuthorizationRequest(request)
		assert.NoError(t, err)
		assert.Equal(t, Plain, request.CodeChallengeMethod)
	})
}

func createClientRegistrationRequest() *ClientRegistrationRequest {
	return &ClientRegistrationRequest{
		Name:          "Test Client",
		Type:          Public,
		RedirectURIS:  []string{"https://www.example-app.com/callback", "myapp://callback"},
		GrantTypes:    []string{AuthorizationCode, PKCE},
		Scopes:        []string{ClientRead, ClientWrite},
		ResponseTypes: []string{CodeResponseType, IDTokenResponseType},
	}
}

func createClientUpdateRequest() *ClientUpdateRequest {
	return &ClientUpdateRequest{
		Name:          "Test Client",
		Type:          Public,
		RedirectURIS:  []string{"https://www.example-app.com/callback", "myapp://callback"},
		GrantTypes:    []string{AuthorizationCode, PKCE},
		Scopes:        []string{ClientRead, ClientWrite},
		ResponseTypes: []string{CodeResponseType, IDTokenResponseType},
	}
}
