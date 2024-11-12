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
	"errors"
	"fmt"
	"github.com/vigiloauth/vigilo/internal/log"
)

type InMemoryDatabase struct {
	data map[string]interface{}
}

func NewInMemoryDatabase() *InMemoryDatabase {
	return &InMemoryDatabase{
		data: make(map[string]interface{}),
	}
}

func (db *InMemoryDatabase) Create(key string, value interface{}) error {
	if db.recordExists(key) {
		err := errors.New("record already exists")
		log.Error(err)
		return err
	}

	db.data[key] = value
	log.Info(fmt.Sprintf("Record successfully added: %s", key))
	return nil
}

func (db *InMemoryDatabase) Read(key string) (interface{}, error) {
	if !db.recordExists(key) {
		err := errors.New("record does not exist")
		log.Error(err)
		return nil, err
	}

	log.Info(fmt.Sprintf("Record found: %s", key))
	return db.data[key], nil
}

func (db *InMemoryDatabase) Update(key string, value interface{}) error {
	if !db.recordExists(key) {
		err := errors.New("record does not exist")
		log.Error(err)
		return err
	}

	db.data[key] = value
	log.Info(fmt.Sprintf("Updated record: %s", key))
	return nil
}

func (db *InMemoryDatabase) Delete(key string) error {
	if !db.recordExists(key) {
		err := errors.New("record does not exist")
		log.Error(err)
		return err
	}

	delete(db.data, key)
	log.Info(fmt.Sprintf("Record deleted: %s", key))
	return nil
}

func (db *InMemoryDatabase) recordExists(key string) bool {
	_, exists := db.data[key]
	return exists
}
