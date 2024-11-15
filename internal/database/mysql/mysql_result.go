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

type SQLResult struct {
	result sql.Result
}

func NewMySQLResult(result sql.Result) *SQLResult {
	return &SQLResult{result: result}
}

func (r *SQLResult) LastInsertId() (int64, error) {
	return r.result.LastInsertId()
}

func (r *SQLResult) RowsAffected() (int64, error) {
	return r.result.RowsAffected()
}
