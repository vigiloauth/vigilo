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

package models

import (
	"fmt"
	"github.com/vigiloauth/vigilo/internal/clients"
	"github.com/vigiloauth/vigilo/pkg/config"
)

type ClientRegistrationRequest struct {
	Name            string                  `json:"name"`
	RedirectURIs    []string                `json:"redirect_uris"`
	ApplicationType clients.ApplicationType `json:"application_type"`
	GrantTypes      []config.GrantType      `json:"grant_types"`
	Scopes          *string                 `json:"scope,omitempty"`
	RequirePKCE     bool                    `json:"require_pkce_pkce"`
}

func (req *ClientRegistrationRequest) Validate() error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}

	if req.RedirectURIs == nil || len(req.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris is required")
	}

	if req.ApplicationType == "" {
		return fmt.Errorf("client_type is required")
	}

	if req.GrantTypes == nil || len(req.GrantTypes) == 0 {
		return fmt.Errorf("grant_type is required")
	}

	if err := req.validatePKCESupport(); err != nil {
		return fmt.Errorf("invalid PKCESupport: %w", err)
	}

	return nil
}

func (req *ClientRegistrationRequest) validatePKCESupport() error {
	switch config.GetAuthConfig().PKCEEnforcementMode {
	case config.PKCEDisabled:
		return nil
	case config.PKCEWarn:
		if !req.RequirePKCE {
			fmt.Println("WARNING: Client registered without PKCE support")
		}
		return nil
	case config.PKCERequired:
		if !req.RequirePKCE {
			return fmt.Errorf("PKCE is required for client registration")
		}
		return nil
	default:
		return fmt.Errorf("invalid PKCE enforcement mode")
	}
}
