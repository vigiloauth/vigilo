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

package repository

import (
	"fmt"
	"github.com/vigiloauth/vigilo/internal/database/interfaces"
	"github.com/vigiloauth/vigilo/internal/models"
)

type ClientRepository struct {
	db interfaces.ClientDatabase
}

func NewClientRepository(db interfaces.ClientDatabase) *ClientRepository {
	return &ClientRepository{db: db}
}

func (repo *ClientRepository) Create(client *models.Client) error {
	if err := repo.db.Create(client.ID, *client); err != nil {
		return fmt.Errorf("error creating client: %w", err)
	}

	return nil
}

func (repo *ClientRepository) FindById(id string) (*models.Client, error) {
	client, err := repo.db.Read(id)
	if err != nil {
		return nil, fmt.Errorf("error retrieving client: %w", err)
	}

	return client, err
}

func (repo *ClientRepository) Update(client *models.Client) error {
	if err := repo.db.Update(client.ID, *client); err != nil {
		return fmt.Errorf("error updating client: %w", err)
	}

	return nil
}

func (repo *ClientRepository) Delete(id string) error {
	if err := repo.db.Delete(id); err != nil {
		return fmt.Errorf("error deleting client: %w", err)
	}
	return nil
}
