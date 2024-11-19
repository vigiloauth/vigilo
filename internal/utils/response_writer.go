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

package utils

import (
	"encoding/json"
	"github.com/vigiloauth/vigilo/internal/errors"
	"net/http"
)

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		panic(err)
	}
}

func WriteError(w http.ResponseWriter, err error) {
	var status int
	var response interface{}

	switch e := err.(type) {
	case *errors.BadRequestError:
		status = http.StatusBadRequest
		response = &ErrorResponse{
			Error:       "bad_request",
			Description: e.Error(),
		}
	case *errors.ValidationError:
		status = http.StatusBadRequest
		response = &ErrorResponse{
			Error:       "validation_error",
			Description: e.Error(),
		}

	default:
		status = http.StatusInternalServerError
		response = &ErrorResponse{
			Error:       "internal_server_error",
			Description: "An unexpected error occurred",
		}
	}

	WriteJSON(w, status, response)
}
