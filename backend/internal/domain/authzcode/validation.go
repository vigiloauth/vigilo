package domain

import "github.com/vigiloauth/vigilo/v2/internal/errors"

func (c *AuthorizationCodeData) ValidateFields(clientID, redirectURI string) error {
	if c.Used {
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code has already been used")
	} else if c.ClientID != clientID {
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code client ID and request client ID do no match")
	} else if c.RedirectURI != redirectURI {
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code redirect URI and request redirect URI do no match")
	}

	return nil
}
