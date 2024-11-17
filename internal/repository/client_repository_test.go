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

package repository

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/mocks"
	"github.com/vigiloauth/vigilo/internal/models"
	"testing"
)

func TestClientRepository_Create(t *testing.T) {
	tests := []struct {
		name          string
		client        *models.Client
		mockError     error
		expectedError bool
	}{
		{
			name:          "Success",
			client:        &models.Client{ID: "123"},
			mockError:     nil,
			expectedError: false,
		}, {
			name:          "Error",
			client:        &models.Client{ID: "123"},
			mockError:     fmt.Errorf("database error"),
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockDB := new(mocks.MockClientDatabase)
			repo := NewClientRepository(mockDB)
			mockDB.On("Create", test.client.ID, *test.client).Return(test.mockError)

			err := repo.Create(test.client)
			if test.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockDB.AssertExpectations(t)
		})
	}
}

func TestClientRepository_FindById(t *testing.T) {
	tests := []struct {
		name          string
		client        *models.Client
		mockError     error
		expectedError bool
	}{
		{
			name:          "Success",
			client:        &models.Client{ID: "123"},
			mockError:     nil,
			expectedError: false,
		}, {
			name:          "Error",
			client:        &models.Client{ID: "123"},
			mockError:     fmt.Errorf("database error"),
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockDB := new(mocks.MockClientDatabase)
			repo := NewClientRepository(mockDB)
			mockDB.On("Read", test.client.ID).Return(test.client, test.mockError)

			client, err := repo.FindById(test.client.ID)
			if test.expectedError {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
			mockDB.AssertExpectations(t)
		})
	}
}

func TestClientRepository_Update(t *testing.T) {
	tests := []struct {
		name          string
		client        *models.Client
		mockError     error
		expectedError bool
	}{
		{
			name:          "Success",
			client:        &models.Client{ID: "123"},
			mockError:     nil,
			expectedError: false,
		}, {
			name:          "Error",
			client:        &models.Client{ID: "123"},
			mockError:     fmt.Errorf("database error"),
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockDB := new(mocks.MockClientDatabase)
			repo := NewClientRepository(mockDB)
			mockDB.On("Update", test.client.ID, *test.client).Return(test.mockError)

			err := repo.Update(test.client)
			if test.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockDB.AssertExpectations(t)
		})
	}
}

func TestClientRepository_Delete(t *testing.T) {
	tests := []struct {
		name          string
		client        *models.Client
		mockError     error
		expectedError bool
	}{
		{
			name:          "Success",
			client:        &models.Client{ID: "123"},
			mockError:     nil,
			expectedError: false,
		}, {
			name:          "Error",
			client:        &models.Client{ID: "123"},
			mockError:     fmt.Errorf("database error"),
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mockDB := new(mocks.MockClientDatabase)
			repo := NewClientRepository(mockDB)
			mockDB.On("Delete", test.client.ID).Return(test.mockError)

			err := repo.Delete(test.client.ID)
			if test.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockDB.AssertExpectations(t)
		})
	}
}
