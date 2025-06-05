package tests

import (
	"net/url"
	"testing"

	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
)

func FuzzNewClientAuthorizationRequest(f *testing.F) {
	f.Add("client_id=abc&redirect_uri=https://evil.com&response_type=code")
	f.Fuzz(func(t *testing.T, raw string) {
		values, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		_ = client.NewClientAuthorizationRequest(values)
	})
}
