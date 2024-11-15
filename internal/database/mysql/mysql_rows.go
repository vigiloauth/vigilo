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
)

type SQLRows struct {
	rows *sql.Rows
}

func NewSQLRows(rows *sql.Rows) *SQLRows {
	return &SQLRows{rows: rows}
}

func (r *SQLRows) Next() bool {
	return r.rows.Next()
}

func (r *SQLRows) Scan(dest ...interface{}) error {
	return r.rows.Scan(dest...)
}

func (r *SQLRows) Close() error {
	return r.rows.Close()
}

func (r *SQLRows) Err() error {
	return r.rows.Err()
}
