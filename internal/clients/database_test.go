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

import "testing"

func TestInMemoryClientDatabase_Create(t *testing.T) {
	tests := []struct {
		name    string
		client  *Client
		wantErr bool
	}{
		{
			name:    "Create new client",
			client:  &Client{ID: "1", Name: "John Doe"},
			wantErr: false,
		}, {
			name:    "Create client with existing ID",
			client:  &Client{ID: "1", Name: "Jane Doe"},
			wantErr: true,
		},
	}

	db := NewInMemoryDatabase()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := db.Create(test.client)
			if (err != nil) != test.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestInMemoryClientDatabase_Read(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		expected *Client
		wantErr  bool
	}{
		{
			name:     "Read existing client",
			id:       "1",
			expected: &Client{ID: "1", Name: "John Doe"},
			wantErr:  false,
		}, {
			name:     "Read non-existent client",
			id:       "2",
			expected: nil,
			wantErr:  true,
		},
	}

	db := NewInMemoryDatabase()
	err := db.Create(&Client{ID: "1", Name: "John Doe"})
	if err != nil {
		t.Errorf("unexpected error creating client: %v", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := db.Read(test.id)
			if (err != nil) != test.wantErr {
				t.Errorf("Read() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && client.ID != test.expected.ID {
				t.Errorf("Read() = %v, want %v", client, test.expected)
			}
		})
	}
}

func TestInMemoryClientDatabase_Update(t *testing.T) {
	tests := []struct {
		name    string
		client  *Client
		wantErr bool
	}{
		{
			name:    "Update existing client",
			client:  &Client{ID: "1", Name: "John Doe Updated"},
			wantErr: false,
		}, {
			name:    "Update non-existent client",
			client:  &Client{ID: "2", Name: "Non-existent Client"},
			wantErr: true,
		},
	}

	db := NewInMemoryDatabase()
	err := db.Create(&Client{ID: "1", Name: "John Doe"})
	if err != nil {
		t.Errorf("unexpected error creating client: %v", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := db.Update(test.client)
			if (err != nil) != test.wantErr {
				t.Errorf("Update() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestInMemoryClientDatabase_Delete(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{
			name:    "Delete existing client",
			id:      "1",
			wantErr: false,
		}, {
			name:    "Delete non-existent client",
			id:      "2",
			wantErr: true,
		},
	}

	db := NewInMemoryDatabase()
	err := db.Create(&Client{ID: "1", Name: "John Doe"})
	if err != nil {
		t.Errorf("unexpected error creating client: %v", err)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := db.Delete(test.id)
			if (err != nil) != test.wantErr {
				t.Errorf("Delete() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
