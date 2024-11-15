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

package models

import "time"

type ClientCredentialsGrant struct {
	ClientID     string
	ClientSecret string
	ExpiresAt    time.Time
}

func NewClientCredentialsGrant(clientID, clientSecret string) *ClientCredentialsGrant {
	return &ClientCredentialsGrant{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ExpiresAt:    time.Now().Add(30 * time.Minute).UTC(),
	}
}
