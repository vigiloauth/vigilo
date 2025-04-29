# User Guide for VigiloAuth

Welcome to the **VigiloAuth** User Guide! This guide will help you get started with integrating **VigiloAuth** into your project, configuring it to meet your needs, and understanding its features.

---

## Table of Contents
- [User Guide for VigiloAuth](#user-guide-for-vigiloauth)
	- [Table of Contents](#table-of-contents)
	- [1. Overview](#1-overview)
	- [2. Features](#2-features)
	- [3. Getting Started](#3-getting-started)
		- [3.1 Installation](#31-installation)
		- [3.2 Configuration](#32-configuration)
	- [4. Quick Start](#4-quick-start)
	- [5. Contributing](#5-contributing)
		- [5.1 How to Contribute](#51-how-to-contribute)
		- [5.2 Commit Standards](#52-commit-standards)
		- [5.3 Commit Types](#53-commit-types)
	- [6. License](#6-license)

---

## 1. Overview

**VigiloAuth** is a library designed to simplify authentication and identity management in your application. It provides robust support for OAuth 2.0, token-based authentication, and secure identity workflows.

Whether you're building a web application, API, or microservices architecture, **VigiloAuth** offers the tools you need to manage user authentication and authorization efficiently.

---

## 2. Features

- **OAuth 2.0 Support**: Built-in support for common grant types, including authorization code, client credentials, and refresh tokens.
- **Token Management**: Securely generate, validate, and manage access and refresh tokens.
- **Customizable Configuration**: Easily configure endpoints, token lifetimes, and client settings.
- **Machine-to-Machine Communication**: Support for client credentials flow for secure server-to-server communication.
- **Developer-Friendly**: Comprehensive documentation and examples to help you get started quickly.

---

## 3. Getting Started

### 3.1 Installation
VigiloAuth offers two ways to run your own authentication server: as a library implementation or as a standalone Docker instance. To decide which version to use, refer to the installation guides below:
- [Library Installation Guide](./configuration/library.md)
- [Docker Installation Guide](./configuration/docker.md)

Ensure you have the following prerequisites:

- **Go**: Version 1.18 or higher.
- **Dependencies**: See our `go.mod` file for required dependencies.

### 3.2 Configuration
For a deeper understanding of how our configurations work, refer to the following guide:
- [VigiloAuth Configuration Guide](./configuration/configuration_guide.md)

---

## 4. Quick Start

Here’s a minimal example to get you started with **VigiloAuth**:

```go
package main

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/v2/identity/server"
	"github.com/vigiloauth/vigilo/v2/identity/config"
	"net/http"
)

func main() {
	appRouter := chi.NewRouter() 
	
    // Initialize the VigiloIdentityServer with default configuration
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	
	// Retrieve the Vigilo Identity router.
	vigiloIdentityRouter := vigiloIdentityServer.Router()
	
	// Mount the VigiloIdentity router to your application's router.
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