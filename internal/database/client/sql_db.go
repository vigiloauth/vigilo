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
	"github.com/vigiloauth/vigilo/internal/database/mysql"
	"github.com/vigiloauth/vigilo/internal/models"
)

type SQLClientDatabase struct {
	connection *mysql.SQLConnection
}

func NewSQLClientDB(connection *mysql.SQLConnection) *SQLClientDatabase {
	return &SQLClientDatabase{connection: connection}
}

func (db *SQLClientDatabase) Create(key string, client models.Client) error {
	return fmt.Errorf("method not yet implemented")
}

func (db *SQLClientDatabase) Read(key string) (*models.Client, error) {
	return nil, fmt.Errorf("method not yet implemented")
}

func (db *SQLClientDatabase) Update(key string, client models.Client) error {
	return fmt.Errorf("method not yet implemented")
}

func (db *SQLClientDatabase) Delete(key string) error {
	return fmt.Errorf("method not yet implemented")
}
