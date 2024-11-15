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

package mysql

import (
	"database/sql"
	"github.com/vigiloauth/vigilo/internal/database/interfaces"
)

type SQLConnection struct {
	db *sql.DB
}

func NewSQLConnection(db *sql.DB) *SQLConnection {
	return &SQLConnection{db: db}
}

func (c *SQLConnection) Ping() error {
	return c.db.Ping()
}

func (c *SQLConnection) Close() error {
	return c.db.Close()
}

func (c *SQLConnection) Begin() (interfaces.Transaction, error) {
	tx, err := c.db.Begin()
	if err != nil {
		return nil, err
	}
	return &SQLTransaction{tx: tx}, nil
}

func (c *SQLConnection) Exec(query string, args ...interface{}) (interfaces.Result, error) {
	res, err := c.db.Exec(query, args...)
	if err != nil {
		return nil, err
	}
	return &SQLResult{result: res}, nil
}

func (c *SQLConnection) Query(query string, args ...interface{}) (interfaces.Rows, error) {
	rows, err := c.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	return &SQLRows{rows: rows}, nil
}

func (c *SQLConnection) QueryRow(query string, args ...interface{}) interfaces.Row {
	return &SQLRow{row: c.db.QueryRow(query, args...)}
}
