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
	"github.com/vigiloauth/vigilo/pkg/client/types"
	"time"
)

type Client struct {
	ID           string
	Secret       *string
	Name         string
	CreatedAt    time.Time
	UpdatedAt    *time.Time
	GrantTypes   []types.GrantTypeEnum
	RedirectURIs []string
	ClientType   types.ClientTypeEnum
}

func NewClient(name string, grantTypes []types.GrantTypeEnum, redirectURIs []string, clientType types.ClientTypeEnum) *Client {
	client := &Client{
		ID:           uuid.New().String(),
		Name:         name,
		CreatedAt:    time.Now(),
		UpdatedAt:    nil,
		GrantTypes:   grantTypes,
		RedirectURIs: redirectURIs,
		ClientType:   clientType,
	}

	if clientType == types.Confidential {
		secret := uuid.New().String()
		client.Secret = &secret
	}

	return client
}
