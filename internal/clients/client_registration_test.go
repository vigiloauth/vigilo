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

package clients

import (
	"github.com/vigiloauth/vigilo/pkg/config"
	"testing"
)

const validRedirectURI = "https://example.com/callback"

func TestRegistration_Register(t *testing.T) {
	clientRegistration := &Registration{db: NewInMemoryDatabase()}

	tests := []struct {
		name             string
		req              *Client
		mockReadReturn   *Client
		mockCreateReturn error
		wantErr          bool
	}{
		{
			name:             "Register new client",
			req:              createClient(validRedirectURI),
			mockReadReturn:   nil,
			mockCreateReturn: nil,
			wantErr:          false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := clientRegistration.Register(*test.req)
			if (err != nil) != test.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestRegistration_URIValidationLogic(t *testing.T) {
	clientRegistration := &Registration{db: NewInMemoryDatabase()}

	tests := []struct {
		name             string
		req              *Client
		mockCreateReturn error
		wantErr          bool
	}{
		{
			name:             "Valid redirect URI",
			req:              createClient(validRedirectURI),
			mockCreateReturn: nil,
			wantErr:          false,
		}, {
			name:             "Invalid scheme",
			req:              createClient("http://invalid.com/callback"),
			mockCreateReturn: nil,
			wantErr:          true,
		}, {
			name:             "URI contains fragment",
			req:              createClient("https://invalid.com/call#back"),
			mockCreateReturn: nil,
			wantErr:          true,
		}, {
			name:             "Empty hostname",
			req:              createClient("https://"),
			mockCreateReturn: nil,
			wantErr:          true,
		}, {
			name:             "Empty redirect URIs",
			req:              createClient(""),
			mockCreateReturn: nil,
			wantErr:          true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := clientRegistration.Register(*test.req)
			if (err != nil) != test.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func createClient(redirectURI string) *Client {
	return &Client{
		Name:         "test client",
		RedirectURIs: []string{redirectURI},
		Type:         Confidential,
		GrantTypes:   []config.GrantType{config.AuthorizationCode},
	}
}
