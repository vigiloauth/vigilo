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
	"github.com/vigiloauth/vigilo/internal/client/models"
	"github.com/vigiloauth/vigilo/internal/mocks"
	"testing"
)

func setupTest(t *testing.T) (*mocks.MockDatabase, *Registration) {
	mockDB := mocks.NewMockDatabase()
	clientRegistration := NewRegistration(mockDB)

	t.Cleanup(func() { mockDB = mocks.NewMockDatabase() })

	return mockDB, clientRegistration
}

func TestRegisterClient_ValidData(t *testing.T) {
	mockDB, clientRegistration := setupTest(t)

	client := models.Client{ID: "client123", Name: "Test Client"}

	err := clientRegistration.RegisterClient(client)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	_, err = mockDB.Read(client.ID)
	if err != nil {
		t.Fatalf("Expected client to be in the database, but got error: %v", err)
	}
}

func TestRegisterClient_InvalidData(t *testing.T) {
	mockDB, clientRegistration := setupTest(t)

	client := models.Client{ID: "client123", Name: "Test Client"}
	_ = mockDB.Create(client.ID, client)

	err := clientRegistration.RegisterClient(client)
	if err == nil {
		t.Fatalf("Expected error for already existing client, got none.")
	}
}
