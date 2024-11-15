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

package config

import (
	"github.com/stretchr/testify/assert"
	"github.com/vigiloauth/vigilo/internal/config"
	"testing"
)

func setup() {
	config.GetInstance()
	instance := config.GetInstance()
	instance.Connection = nil
}

func TestConfigureDatabase_ReturnsNoError(t *testing.T) {
	setup()
	connectionString := "mysql://username:password@localhost:8080/my_db"
	err := ConnectDatabase(connectionString)

	assert.Nil(t, err, "Error should be nil")
	assert.NoError(t, err, "ConnectDatabase should not return an error")
	assert.NotNil(t, config.GetConnection(), "Connection should not be nil")
}

func TestConfigureDatabase_ReturnsError(t *testing.T) {
	setup()
	connectionString := "oracle://username@localhost:8080"
	err := ConnectDatabase(connectionString)

	assert.NotNil(t, err, "ConnectDatabase should return an error")
	assert.Error(t, err, "ConnectDatabase should return an error")
	assert.Nil(t, config.GetConnection(), "Connection should be nil")
}
