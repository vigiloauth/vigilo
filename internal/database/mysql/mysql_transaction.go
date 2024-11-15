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
	"fmt"
)

type SQLTransaction struct {
	tx *sql.Tx
}

func NewTransaction(db *sql.DB) (*SQLTransaction, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %v", err)
	}
	return &SQLTransaction{tx: tx}, nil
}

func (t *SQLTransaction) Commit() error {
	if t.tx == nil {
		return fmt.Errorf("transaction not initialized")
	}

	err := t.tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}
	return nil
}

func (t *SQLTransaction) Rollback() error {
	if t.tx == nil {
		return fmt.Errorf("transaction not initialized")
	}

	err := t.tx.Rollback()
	if err != nil && err != sql.ErrTxDone {
		// If the transaction was already committed or rolled back, sql.ErrTxDone is expected.
		return fmt.Errorf("failed to roll back transaction: %v", err)
	}
	return nil
}
