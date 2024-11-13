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

package database

import (
	"fmt"
	"sync"
)

type InMemoryDatabase struct {
	data map[string]interface{}
	mu   sync.RWMutex
}

func NewInMemoryDatabase() *InMemoryDatabase {
	return &InMemoryDatabase{data: make(map[string]interface{})}
}

func (db *InMemoryDatabase) Create(key string, value interface{}) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[key]; exists {
		return fmt.Errorf("create operation failed: record with key '%s' already exists", key)
	}

	db.data[key] = value
	return nil
}

func (db *InMemoryDatabase) Read(key string) (interface{}, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	value, exists := db.data[key]
	if !exists {
		return nil, fmt.Errorf("read operation failed: no record found with key '%s'", key)
	}

	return value, nil
}

func (db *InMemoryDatabase) Update(key string, value interface{}) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[key]; !exists {
		return fmt.Errorf("update operation failed: no record found with key '%s'", key)
	}

	db.data[key] = value
	return nil
}

func (db *InMemoryDatabase) Delete(key string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[key]; !exists {
		return fmt.Errorf("delete operation failed: no record found with key '%s'", key)
	}

	delete(db.data, key)
	return nil
}
