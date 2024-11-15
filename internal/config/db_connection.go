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
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/vigiloauth/vigilo/internal/database/mysql"
	"net/url"
	"strings"
)

func CreateDatabaseConnection(connectionString string) error {
	formattedConnectionString, err := formatConnectionString(connectionString)
	if err != nil {
		return fmt.Errorf("invalid connection string format: %w", err)
	}

	connection, err := sql.Open("mysql", formattedConnectionString)
	if err != nil {
		return fmt.Errorf("failed to establish database connection: %w", err)
	}

	sqlConnection := mysql.NewSQLConnection(connection)
	instance := GetInstance()
	instance.Mu.Lock()
	defer instance.Mu.Unlock()
	instance.Connection = sqlConnection

	return nil
}

func formatConnectionString(connectionString string) (string, error) {
	u, err := url.Parse(connectionString)
	if err != nil {
		return "", err
	}

	username := u.User.Username()
	password, _ := u.User.Password()
	hostname := u.Hostname()
	port := u.Port()
	dbName := strings.TrimPrefix(u.Path, "/")

	if err := checkForMissingFields(username, password, hostname, port, dbName); err != nil {
		return "", err
	}

	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", username, password, hostname, port, dbName), nil
}

func checkForMissingFields(username, password, hostname, port, dbName string) error {
	var missingFields []string

	if username == "" {
		missingFields = append(missingFields, "username")
	}
	if password == "" {
		missingFields = append(missingFields, "password")
	}
	if hostname == "" {
		missingFields = append(missingFields, "hostname")
	}
	if port == "" {
		missingFields = append(missingFields, "port")
	}
	if dbName == "" {
		missingFields = append(missingFields, "db name")
	}

	if len(missingFields) > 0 {
		return fmt.Errorf("missing required field(s): %s", strings.Join(missingFields, ", "))
	}

	return nil
}
