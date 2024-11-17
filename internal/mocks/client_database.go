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
	"github.com/stretchr/testify/mock"
	"github.com/vigiloauth/vigilo/internal/models"
)

type MockClientDatabase struct {
	mock.Mock
}

func (m *MockClientDatabase) Create(id string, client models.Client) error {
	args := m.Called(id, client)
	return args.Error(0)
}

func (m *MockClientDatabase) Read(id string) (*models.Client, error) {
	args := m.Called(id)
	if client, ok := args.Get(0).(*models.Client); ok {
		return client, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockClientDatabase) Update(id string, client models.Client) error {
	args := m.Called(id, client)
	return args.Error(0)
}

func (m *MockClientDatabase) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}
