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

package test

import (
	"github.com/vigiloauth/vigilo/internal/database"
	"testing"
)

func TestCreate(t *testing.T) {
	db := database.NewInMemoryDatabase()
	err := db.Create("1", "First Record")
	if err != nil {
		t.Errorf("Create failed: %v", err)
	}

	err = db.Create("1", "Duplicate Record")
	if err == nil {
		t.Errorf("Expected error for duplicate record creation, but got nil.")
	}
}

func TestRead(t *testing.T) {
	db := database.NewInMemoryDatabase()
	_ = db.Create("1", "First Record")

	value, err := db.Read("1")
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if value != "First Record" {
		t.Errorf("Read failed: expected %v, got %v", value, "First Record")
	}
}

func TestReadForNonExistingRecord(t *testing.T) {
	db := database.NewInMemoryDatabase()
	_, err := db.Read("non-existent-key")
	if err == nil {
		t.Errorf("Expected error 'record does not exist', got nil")
	} else if err.Error() != "record does not exist" {
		t.Errorf("Expected error 'record does not exist', got %v", err)
	}
}

func TestUpdate(t *testing.T) {
	db := database.NewInMemoryDatabase()
	_ = db.Create("1", "First Record")

	err := db.Update("1", "Updated Record")
	if err != nil {
		t.Errorf("Update failed: %v", err)
	}

	err = db.Update("2", "New Record")
	if err == nil {
		t.Errorf("Expected error for updating non-existent key, but got nil.")
	}
}

func TestDelete(t *testing.T) {
	db := database.NewInMemoryDatabase()
	_ = db.Create("1", "First Record")

	err := db.Delete("1")
	if err != nil {
		t.Errorf("Delete failed: %v", err)
	}

	err = db.Delete("2")
	if err == nil {
		t.Errorf("Expected error for deleting non-existent key, but got nil.")
	}
}
