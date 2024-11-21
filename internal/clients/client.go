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

import "time"

type ApplicationType string
type GrantType string

const (
	Confidential ApplicationType = "confidential"
	Public       ApplicationType = "public"

	AuthorizationCode GrantType = "authorization_code"
	Implicit          GrantType = "implicit"
	ClientCredentials GrantType = "client_credentials"
	Password          GrantType = "password"
	PKCE              GrantType = "pkce"
)

type Client struct {
	Name         string
	ID           string
	Secret       *string
	RedirectURIs []string
	Type         ApplicationType
	GrantTypes   []GrantType
	Scopes       *string
	CreatedAt    time.Time
	UpdatedAt    *time.Time
	RequirePKCE  bool
}
