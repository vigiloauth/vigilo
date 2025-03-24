package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientRegistrationRequest_ValidatePublicClient(t *testing.T) {
	t.Run("Successful Validation", func(t *testing.T) {
		client := createPublicClientRegistrationRequest()
		err := client.Validate()
		assert.NoError(t, err)
	})

	t.Run("Invalid Client Type", func(t *testing.T) {
		client := createPublicClientRegistrationRequest()
		client.Type = Confidential

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Grant Types", func(t *testing.T) {
		client := createPublicClientRegistrationRequest()
		client.GrantTypes = append(client.GrantTypes, ClientCredentials)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Redirect URIS", func(t *testing.T) {
		invalidRedirectURI := "http:/missing-slash/callback"
		client := createPublicClientRegistrationRequest()
		client.RedirectURIS = append(client.RedirectURIS, invalidRedirectURI)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Scopes", func(t *testing.T) {
		invalidScope := "update"
		client := createPublicClientRegistrationRequest()
		client.Scopes = append(client.Scopes, invalidScope)

		err := client.Validate()
		assert.Error(t, err)
	})

	t.Run("Invalid Response Types", func(t *testing.T) {
		client := createPublicClientRegistrationRequest()
		client.ResponseTypes = []ResponseType{TokenResponseType}

		err := client.Validate()
		assert.Error(t, err)
	})
}

func createPublicClientRegistrationRequest() *ClientRegistrationRequest {
	return &ClientRegistrationRequest{
		Name:          "Test Client",
		Type:          Public,
		RedirectURIS:  []string{"https://www.example-app.com/callback", "myapp://callback"},
		GrantTypes:    []GrantType{AuthorizationCode, PKCE},
		Scopes:        []string{ClientRead, ClientWrite},
		ResponseTypes: []ResponseType{CodeResponseType, IDTokenResponseType},
	}
}
