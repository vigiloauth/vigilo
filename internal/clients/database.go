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
	"sync"
)

type InMemoryDatabase struct {
	data map[string]Client
	mu   sync.RWMutex
}

func NewInMemoryDatabase() *InMemoryDatabase {
	return &InMemoryDatabase{data: make(map[string]Client)}
}

func (db *InMemoryDatabase) Create(client *Client) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[client.ID]; exists {
		return fmt.Errorf("client already exists with the given id")
	}

	db.data[client.ID] = *client
	return nil
}

func (db *InMemoryDatabase) Read(id string) (*Client, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if client, exists := db.data[id]; exists {
		return &client, nil
	}

	return nil, fmt.Errorf("client doesn't exist with the given id")
}

func (db *InMemoryDatabase) Update(client *Client) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[client.ID]; !exists {
		return fmt.Errorf("client doesn't exist with the given id")
	}

	db.data[client.ID] = *client
	return nil
}

func (db *InMemoryDatabase) Delete(id string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[id]; !exists {
		return fmt.Errorf("client doesn't exist with the given id")
	}

	delete(db.data, id)
	return nil
}
