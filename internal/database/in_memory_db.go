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
	"log/slog"
	"os"
)

var logger = slog.New(slog.NewTextHandler(os.Stdout, nil))

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
		logger.Error(err.Error())
		return err
	}

	db.data[key] = value
	logger.Info("Record successfully added.")
	return nil
}

func (db *InMemoryDatabase) Read(key string) (interface{}, error) {
	if !db.recordExists(key) {
		err := errors.New("record does not exist")
		logger.Error(err.Error())
		return nil, err
	}

	logger.Info("Record found.")
	return db.data[key], nil
}

func (db *InMemoryDatabase) Update(key string, value interface{}) error {
	if !db.recordExists(key) {
		err := errors.New("record does not exist")
		logger.Error(err.Error())
		return err
	}

	db.data[key] = value
	logger.Info("Record successfully updated.")
	return nil
}

func (db *InMemoryDatabase) Delete(key string) error {
	if !db.recordExists(key) {
		err := errors.New("record does not exist")
		logger.Error(err.Error())
		return err
	}

	delete(db.data, key)
	logger.Info("Record successfully deleted.")
	return nil
}

func (db *InMemoryDatabase) recordExists(key string) bool {
	_, exists := db.data[key]
	return exists
}
