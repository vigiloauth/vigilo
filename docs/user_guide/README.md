# User Guide for VigiloAuth

Welcome to the **VigiloAuth** User Guide! This guide will help you get started with integrating **VigiloAuth** into your project, configuring it to meet your needs, and understanding its features.

---

## Table of Contents
- [Overview](#1-overview)
- [Features](#2-features)
- [Getting Started](#3-getting-started)
  - [Installation](#31-installation)
  - [Configuration](#32-configuration)
- [Quick Start](#4-quick-start)
- [Feedback and Contributions](#5-feedback-and-contributions)

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

Follow the [installation guide](installation.md) to add **VigiloAuth** to your project. Ensure you have the following prerequisites:

- **Go**: Version 1.18 or higher.
- **Dependencies**: See the `go.mod` file for required libraries.

### 3.2 Configuration

Learn how to configure endpoints, token lifetimes, and client settings in the [configuration guide](configuration.md). Example configurations include:

- Setting up OAuth endpoints.
- Customizing token expiration times.
- Registering clients and managing scopes.

---

## 4. Quick Start

Here’s a minimal example to get you started with **VigiloAuth**:

```go
package main

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/vigiloauth/vigilo/identity/server"
	"github.com/vigiloauth/vigilo/identity/config"
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