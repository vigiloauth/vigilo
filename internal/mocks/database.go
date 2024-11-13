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

package mocks

import (
	"fmt"
	"sync"
)

type MockDatabase struct {
	mu sync.RWMutex

	CreateFunc func(key string, value interface{}) error
	ReadFunc   func(key string) (interface{}, error)
	UpdateFunc func(key string, value interface{}) error
	DeleteFunc func(key string) error

	CreateCalls []struct {
		Key   string
		Value interface{}
	}
	ReadCalls []struct {
		Key string
	}
	UpdateCalls []struct {
		Key   string
		Value interface{}
	}
	DeleteCalls []struct {
		Key string
	}

	data map[string]interface{}
}

func NewMockDatabase() *MockDatabase {
	db := &MockDatabase{
		data: make(map[string]interface{}),
		CreateCalls: make([]struct {
			Key   string
			Value interface{}
		}, 0),
		ReadCalls: make([]struct {
			Key string
		}, 0),
		UpdateCalls: make([]struct {
			Key   string
			Value interface{}
		}, 0),
		DeleteCalls: make([]struct {
			Key string
		}, 0),
	}

	db.CreateFunc = db.defaultCreate
	db.ReadFunc = db.defaultRead
	db.UpdateFunc = db.defaultUpdate
	db.DeleteFunc = db.defaultDelete

	return db
}

func (db *MockDatabase) defaultCreate(key string, value interface{}) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[key]; exists {
		return fmt.Errorf("create operation failed: record with key '%s' already exists", key)
	}
	db.data[key] = value
	return nil
}

func (db *MockDatabase) defaultRead(key string) (interface{}, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	value, exists := db.data[key]
	if !exists {
		return nil, fmt.Errorf("read operation failed: no record found with key '%s'", key)
	}
	return value, nil
}

func (db *MockDatabase) defaultUpdate(key string, value interface{}) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[key]; !exists {
		return fmt.Errorf("update operation failed: no record found with key '%s'", key)
	}
	db.data[key] = value
	return nil
}

func (db *MockDatabase) defaultDelete(key string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.data[key]; !exists {
		return fmt.Errorf("delete operation failed: no record found with key '%s'", key)
	}
	delete(db.data, key)
	return nil
}

func (db *MockDatabase) Create(key string, value interface{}) error {
	db.CreateCalls = append(db.CreateCalls, struct {
		Key   string
		Value interface{}
	}{key, value})
	return db.CreateFunc(key, value)
}

func (db *MockDatabase) Read(key string) (interface{}, error) {
	db.ReadCalls = append(db.ReadCalls, struct {
		Key string
	}{key})
	return db.ReadFunc(key)
}

func (db *MockDatabase) Update(key string, value interface{}) error {
	db.UpdateCalls = append(db.UpdateCalls, struct {
		Key   string
		Value interface{}
	}{key, value})
	return db.UpdateFunc(key, value)
}

func (db *MockDatabase) Delete(key string) error {
	db.DeleteCalls = append(db.DeleteCalls, struct {
		Key string
	}{key})
	return db.DeleteFunc(key)
}

func (db *MockDatabase) Reset() {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.data = make(map[string]interface{})
	db.CreateCalls = nil
	db.ReadCalls = nil
	db.UpdateCalls = nil
	db.DeleteCalls = nil
}
