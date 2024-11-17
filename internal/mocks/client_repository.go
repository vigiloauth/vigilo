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

type MockClientRepository struct {
	mock.Mock
}

func (mock *MockClientRepository) Create(client *models.Client) error {
	args := mock.Called(client)
	return args.Error(0)
}

func (mock *MockClientRepository) FindById(id string) (*models.Client, error) {
	args := mock.Called(id)
	return args.Get(0).(*models.Client), args.Error(1)
}

func (mock *MockClientRepository) Update(client *models.Client) error {
	args := mock.Called(client)
	return args.Error(0)
}

func (mock *MockClientRepository) Delete(id string) error {
	args := mock.Called(id)
	return args.Error(0)
}
