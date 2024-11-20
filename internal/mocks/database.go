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
)

type MockDatabase[T any] struct {
	mock.Mock
}

func (m *MockDatabase[T]) Create(item *T) error {
	args := m.Called(item)
	return args.Error(0)
}

func (m *MockDatabase[T]) Read(id string) (*T, error) {
	args := m.Called(id)
	if args.Get(0) != nil {
		return args.Get(0).(*T), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockDatabase[T]) Update(item *T) error {
	args := m.Called(item)
	return args.Error(0)
}

func (m *MockDatabase[T]) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}
