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
)

type Registration struct {
	ClientStore database.Database
}

func NewRegistration(clientStore database.Database) *Registration {
	return &Registration{ClientStore: clientStore}
}

func (r *Registration) RegisterClient(client models.Client) error {
	err := r.ClientStore.Create(client.ID, client)
	if err != nil {
		return fmt.Errorf("client registration failed for client with ID '%s': %v", client.ID, err)
	}

	return nil
}
