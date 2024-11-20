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
)

type ClientRegistrationRequest struct {
	Name         string              `json:"name"`
	RedirectURIs []string            `json:"redirect_uris"`
	ClientType   clients.ClientType  `json:"client_type"`
	GrantTypes   []clients.GrantType `json:"grant_types"`
	Scopes       *string             `json:"scope,omitempty"`
}

func (req *ClientRegistrationRequest) Validate() error {
	if req.Name == "" {
		return fmt.Errorf("name is required")
	}

	if req.RedirectURIs == nil || len(req.RedirectURIs) == 0 {
		return fmt.Errorf("redirect_uris is required")
	}

	if req.ClientType == "" {
		return fmt.Errorf("client_type is required")
	}

	if req.GrantTypes == nil || len(req.GrantTypes) == 0 {
		return fmt.Errorf("grant_type is required")
	}

	return nil
}
