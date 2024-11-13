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
	"github.com/google/uuid"
	"time"
)

type GrantTypeEnum string

const (
	AuthorizationCode GrantTypeEnum = "authorization_code"
	Implicit          GrantTypeEnum = "implicit"
	ClientCredentials GrantTypeEnum = "client_credentials"
	Password          GrantTypeEnum = "password"
)

type ClientTypeEnum string

const (
	Public       ClientTypeEnum = "public"
	Confidential ClientTypeEnum = "confidential"
)

type Client struct {
	ID           string
	Secret       *string
	Name         string
	CreatedAt    time.Time
	UpdatedAt    *time.Time
	GrantTypes   []GrantTypeEnum
	RedirectURIs []string
	ClientType   ClientTypeEnum
}

func NewClient(name string, grantTypes []GrantTypeEnum, redirectURIs []string, clientType ClientTypeEnum) *Client {
	client := &Client{
		ID:           uuid.New().String(),
		Name:         name,
		CreatedAt:    time.Now(),
		UpdatedAt:    nil,
		GrantTypes:   grantTypes,
		RedirectURIs: redirectURIs,
		ClientType:   clientType,
	}

	if clientType == Confidential {
		secret := uuid.New().String()
		client.Secret = &secret
	}

	return client
}
