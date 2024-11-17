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
	"github.com/vigiloauth/vigilo/internal/database/client"
	"github.com/vigiloauth/vigilo/internal/database/interfaces"
	"sync"
)

type GlobalConfig struct {
	ClientDatabase interfaces.ClientDatabase
	Connection     interfaces.Connection
	Mu             sync.RWMutex
}

var (
	instance *GlobalConfig
	once     sync.Once
)

func GetInstance() *GlobalConfig {
	once.Do(func() {
		instance = &GlobalConfig{
			ClientDatabase: client.NewInMemoryClientDB(),
			Connection:     nil,
		}
	})
	return instance
}

func GetConnection() interfaces.Connection {
	instance := GetInstance()
	instance.Mu.RLock()
	defer instance.Mu.RUnlock()
	return instance.Connection
}

func GetClientDatabase() interfaces.ClientDatabase {
	instance := GetInstance()
	instance.Mu.RLock()
	defer instance.Mu.RUnlock()
	return instance.ClientDatabase
}
