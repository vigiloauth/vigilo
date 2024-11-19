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

package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/internal/clients"
	"github.com/vigiloauth/vigilo/internal/constants"
	"github.com/vigiloauth/vigilo/pkg/handlers"
	"net/http"
)

type VigiloServer struct {
	clientHandler *handlers.ClientHandler
	router        chi.Router
}

func NewVigiloServer() *VigiloServer {
	clientHandler := handlers.NewClientHandler(clients.NewRegistration(clients.NewInMemoryDatabase()))
	vs := &VigiloServer{
		clientHandler: clientHandler,
		router:        chi.NewRouter(),
	}

	vs.setupRoutes()
	return vs
}

func (vs *VigiloServer) Handler() http.Handler {
	return vs.router
}

func (vs *VigiloServer) setupRoutes() {
	vs.router.Post(constants.ClientRegistrationURL, vs.clientHandler.HandleClientRegistration)
}
