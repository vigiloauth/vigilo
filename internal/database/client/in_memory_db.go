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
	"errors"
	"github.com/vigiloauth/vigilo/internal/models"
	"sync"
)

type InMemoryClientDatabase struct {
	data map[string]*models.Client
	mu   sync.RWMutex
}

func NewInMemoryClientDB() *InMemoryClientDatabase {
	return &InMemoryClientDatabase{data: make(map[string]*models.Client)}
}

func (db *InMemoryClientDatabase) Create(key string, client models.Client) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	value := db.data[key]
	if value != nil {
		return errors.New("client already exists with the given key")
	}

	db.data[key] = &client
	return nil
}

func (db *InMemoryClientDatabase) Read(key string) (*models.Client, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if _, ok := db.data[key]; !ok {
		return nil, errors.New("client not found with the given key")
	}

	return db.data[key], nil
}

func (db *InMemoryClientDatabase) Update(key string, client models.Client) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, ok := db.data[key]; !ok {
		return errors.New("client not found with the given key")
	}

	db.data[key] = &client
	return nil
}

func (db *InMemoryClientDatabase) Delete(key string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, ok := db.data[key]; !ok {
		return errors.New("client not found with the given key")
	}

	delete(db.data, key)
	return nil
}
