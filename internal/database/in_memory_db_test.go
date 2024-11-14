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
	"github.com/stretchr/testify/assert"
	"testing"
)

func setupTest(t *testing.T) *InMemoryDatabase {
	db := NewInMemoryDatabase()
	t.Cleanup(func() { db = NewInMemoryDatabase() })
	return db
}

func TestCreate(t *testing.T) {
	db := setupTest(t)
	err := db.Create("1", "record")
	assert.NoError(t, err, "Expected no error when inserting a new record")

	err = db.Create("1", "duplicateRecord")
	assert.Error(t, err, "Expected error when inserting a duplicate record")
}

func TestRead(t *testing.T) {
	db := setupTest(t)
	_ = db.Create("1", "record")

	value, err := db.Read("1")
	assert.NotNil(t, value, "Expected value to not be nil")
	assert.NoError(t, err, "Expected no error when retrieving existing value")

	value, err = db.Read("2")
	assert.Nil(t, value, "Expected value to not be nil")
	assert.Error(t, err, "Expected error when retrieving non-existing record")
}

func TestUpdate(t *testing.T) {
	db := setupTest(t)
	_ = db.Create("1", "record")

	err := db.Update("1", "new record")
	assert.NoError(t, err, "Expected no error when updating existing value")

	err = db.Update("2", "non-existing record")
	assert.Error(t, err, "Expected error when updating non-existing value")
}

func TestDelete(t *testing.T) {
	db := NewInMemoryDatabase()
	_ = db.Create("1", "First Record")

	err := db.Delete("1")
	assert.NoError(t, err, "Expected no error when deleting existing value")

	err = db.Delete("2")
	assert.Error(t, err, "Expected error when deleting non-existing value")
}
