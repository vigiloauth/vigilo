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
	"fmt"
	"github.com/vigiloauth/vigilo/internal/config"
)

// ConnectDatabase configures a database to be used by the library. If no connection string is provided,
// the library will default to an In Memory Database.
// Parameters:
//   - connectionString (string): the database connection string.
//
// Returns:
//   - When successful, it returns nil. Meaning the configuration was successful.
//   - On failure, it returns an error that describes what wrong.
func ConnectDatabase(connectionString string) error {
	if err := config.CreateDatabaseConnection(connectionString); err != nil {
		return fmt.Errorf("failed to establish database connection: %s", err)
	}
	return nil
}
