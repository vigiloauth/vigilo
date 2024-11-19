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

package clients

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/vigiloauth/vigilo/internal"
	"github.com/vigiloauth/vigilo/internal/utils"
	"net/url"
	"time"
)

type Registration struct {
	db internal.Database[Client]
}

func NewRegistration(db internal.Database[Client]) *Registration {
	return &Registration{db: db}
}

func (r *Registration) Register(client Client) (*Client, error) {
	if err := r.validateRedirectURIs(client.RedirectURIs); err != nil {
		return nil, err
	}

	client.ID = r.generateClientID()
	if err := r.checkClientExists(client.ID); err != nil {
		return nil, err
	}

	if client.Type == Confidential {
		r.setClientSecret(&client)
	}

	client.CreatedAt = time.Now()
	if err := r.db.Create(&client); err != nil {
		return nil, fmt.Errorf("error creating client: %v", err)
	}

	return &client, nil
}

func (r *Registration) validateRedirectURIs(uris []string) error {
	if err := validateRedirectURIs(uris); err != nil {
		return fmt.Errorf("error validating URIs: %v", err)
	}
	return nil
}

func (r *Registration) generateClientID() string {
	return utils.GenerateHash(uuid.New().String())
}

func (r *Registration) checkClientExists(clientID string) error {
	registeredClient, _ := r.db.Read(clientID)
	if registeredClient != nil {
		return fmt.Errorf("client with ID %s already exists", clientID)
	}
	return nil
}

func (r *Registration) setClientSecret(client *Client) {
	clientSecret := utils.GenerateHash(uuid.New().String())
	client.Secret = &clientSecret
}

func validateRedirectURIs(redirectURIs []string) error {
	if redirectURIs == nil || len(redirectURIs) == 0 {
		return fmt.Errorf("redirect URIs cannot be nil or empty")
	}

	for _, redirectURI := range redirectURIs {
		if err := validateRedirectURI(redirectURI); err != nil {
			return fmt.Errorf("invalid redirect URI: '%s': %v", redirectURI, err)
		}
	}

	return nil
}

func validateRedirectURI(redirectURI string) error {
	parsedURL, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Errorf("invalid redirect URI: '%s': %v", redirectURI, err)
	}

	if parsedURL.Scheme != "https" {
		return fmt.Errorf("scheme must be HTTPS")
	}
	if parsedURL.Host == "" {
		return fmt.Errorf("hostname must not be empty")
	}
	if parsedURL.Fragment != "" {
		return fmt.Errorf("fragments are not allowed")
	}

	return nil
}
