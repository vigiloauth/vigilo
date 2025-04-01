package domain

import (
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
