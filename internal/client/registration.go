/*
 * Copyright 2024 Olivier Pimpare-Charbonneau, Zachary Sexton
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package client

import (
	"fmt"
	"github.com/vigiloauth/vigilo/internal/client/models"
	"github.com/vigiloauth/vigilo/internal/database"
	"github.com/vigiloauth/vigilo/internal/util"
	"net/url"
)

type Registration struct {
	db database.Database
}

func NewRegistration(db database.Database) *Registration {
	return &Registration{db: db}
}

func (r *Registration) RegisterClient(client *models.Client) error {
	client.ID = util.HashSensitiveKey(client.ID)

	if err := validateRedirectURIs(&client.RedirectURIs); err != nil {
		return fmt.Errorf("invalid redirect URIs for: %v", err)
	}

	if err := r.db.Create(client.ID, *client); err != nil {
		return fmt.Errorf("client registration failed: %v", err)
	}

	return nil
}

func validateRedirectURIs(redirectURIs *[]string) error {
	if redirectURIs == nil || len(*redirectURIs) == 0 {
		return fmt.Errorf("redirect URIs cannot be null")
	}

	for _, uri := range *redirectURIs {
		if err := validateRedirectURI(&uri); err != nil {
			return fmt.Errorf("invalid redirect URI '%s': %v", uri, err)
		}
	}

	return nil
}

func validateRedirectURI(redirectURI *string) error {
	if err := util.ValidateURLPattern(redirectURI); err != nil {
		return fmt.Errorf("invalid redirect URI '%s': %v", *redirectURI, err)
	}

	parsedURL, err := url.Parse(*redirectURI)
	if err != nil {
		return fmt.Errorf("malformed URL: %v", err)
	}

	if parsedURL.Scheme != "https" {
		return fmt.Errorf("scheme must be HTTPS")
	}

	if parsedURL.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if parsedURL.Fragment != "" {
		return fmt.Errorf("fragments are not allowed")
	}

	if err := util.ValidateAgainstInvalidChars(redirectURI); err != nil {
		return fmt.Errorf("error validating URL '%s': %v", *redirectURI, err)
	}

	if err := util.ValidateHost(redirectURI); err != nil {
		return fmt.Errorf("error validating URL '%s': %v", *redirectURI, err)
	}

	return nil
}
