# VigiloAuth

![GitHub Release](https://img.shields.io/github/v/release/vigiloauth/vigilo?label=latest%20release)
![Github Repo Starts](https://img.shields.io/github/stars/vigiloauth/vigilo?style=flat)

## Table of Contents
- [Introduction](#1-introduction)
- [Features](#2-features)
- [Documentation](#3-documentation)
- [Getting Started](#4-getting-started)
- [Contributing](#5-contributing)
- [License](#6-license)

## 1. Introduction
⚠️ **Note:** VigiloAuth is currently in development and not yet feature-complete. Some functionalities are still being implemented, and APIs may change in future releases.

VigiloAuth is designed to simplify the implementation of OAuth 2.0 and OpenID Connect (OIDC) authentication servers. Whether you need a full-fledged **authentication server**, an **identity server**, or both, Vigilo provides compliant endpoints that you can easily integrate into your application without writing complex authentication code.

With VigiloAuth, you can quickly set up secure authentication and identity management solutions for you application, allowing users to authenticate and easily manage their identities. The library comes pre-configured with common authentication flows and identity management endpoints, saving you time and effort while making sure that your system complies with industry standards

Whether you are building a simple app or a complex enterprise system, **VigiloAuth** provides a solid foundation for handling authentication and identity management with minimal effort.

## 2. Features
### 2.1 Currently Implemented
- ✅ **User Registration**
    - Allow users to register with basic credentials (e.g., email, password).
    - Includes input validation and error handling.
### 2.2 Planned Features
- 🛠️ **User Login and Authentication** (in progress)
    - OAuth 2.0 and OIDC-compliant login endpoints.
- 🛠️ **Password Recovery**
    - Endpoint for password reset using email verification.
- 🛠️ **User Profile Management**
    - Ability to update user details like email and name.
- 🛠️ **Role-Based Access Control (RBAC)**
    - Assign roles and manage permissions.

## 3. Documentation
Comprehensive documentation is available in the [User Guide](docs/user_guide/README.md).
- [Installation Guide](docs/user_guide/installation.md)
- [Configuration Guide](docs/user_guide/configuration.md)
- [Identity API Endpoints](docs/user_guide/endpoints/identity/README.md)

## 4. Getting Started
To install the library in your application, simply run:
`go get -u github.com/vigiloauth/vigilo@<latest available version>`
```go
package main

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/server"
	"net/http"
)

func main() {
	appRouter := chi.NewRouter()

	vigiloIdentityServer := server.NewVigiloIdentityServer()
	vigiloIdentityRouter := vigiloIdentityServer.Router()
	appRouter.Mount("/identity", vigiloIdentityRouter)

	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", appRouter)
}
```

## 5. Contributing
We welcome contributions to improve VigiloAuth! Follow the steps below to ensure a smooth contribution process.

### 5.1 How to Contribute
1. **Fork the Repository:** Create your own fork of the repository on GitHub.
2. **Clone Your Fork:** Clone your fork locally.
3. **Create a Branch:** Create a feature or a bug fix branch from master.
4. **Make Your Changes:** Implement your changes and ensure they align with the project goals.
5. **Write Tests:** Add or update tests to validate your changes.
6. **Commit Your Changes:** Use **_Conventional Commits_** for all commit messages (see standards below).
7. **Push Your Changes:** Push your branch to your forked repository.
8. **Open a Pull Request (PR):** Submit a PR to the main repository with a clear description of your changes.

### 5.2 Commit Standards
We follow the **_Conventional Commit_** standards to ensure clear and meaningful commit messages. Use the format:
```azure
<type>[optional scope]: <description>
[optional body]
[optional footer(s)]
```
### 5.3 Commit Types
- `breaking`: Introduce a breaking change that may require users to modify their code or dependencies.
- `feat`: Add a new feature that enhances the functionality of the project.
- `fix`: Apply a bug fix that resolves an issue without affecting functionality. 
- `task`: Add or modify internal functionality that supports the codebase but doesn't introduce a new feature or fix a bug (e.g., utility methods, service logic, or internal improvements).
- `chore`: Miscellaneous or updates that aren't features or fixes (e.g., updating build tools, dependencies, or configuration files).
- `docs`: Modify documentation, such as fixing typos or adding new content. 
- `style`: Apply code style or formatting changes that do not affect behavior.
- `refactor`: Restructure existing code without changing its external behavior. 
- `test`: Add or modify tests without affecting functionality. 

## 6. License
Copyright 2024 Olivier Pimparé-Charbonneau

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
