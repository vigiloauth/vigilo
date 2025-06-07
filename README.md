# VigiloAuth

![Latest Version](https://img.shields.io/github/tag/vigiloauth/vigilo?label=latest%20version)
![Github Repo Stars](https://img.shields.io/github/stars/vigiloauth/vigilo?style=flat)
[![Open Source Helpers badge](https://codetriage.com/vigiloauth/vigilo/badges/users.svg)](https://codetriage.com/vigiloauth/vigilo)
[![Go Report](https://goreportcard.com/badge/github.com/vigiloauth/vigilo)](https://goreportcard.com/report/github.com/vigiloauth/vigilo)
[![Go Coverage](https://github.com/vigiloauth/vigilo/wiki/coverage.svg)](https://raw.githack.com/wiki/vigiloauth/vigilo/coverage.html)
[![golangci-lint](https://github.com/vigiloauth/vigilo/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/vigiloauth/vigilo/actions/workflows/golangci-lint.yml)

---

>💡 **VigiloAuth is under active development** and already supports core OAuth2 and OIDC flows, with more on the way!

>⚖️ **Apache 2.0 License:**
This server is free and open source, developed for community use and OIDF certification.

>💬 **Join the Conversation:**
We're gathering feedback and ideas in the discussion threads. Come share your thoughts!

> 💻 The Admin UI can be found [here](https://github.com/vigiloauth/vigilo-ui)

---

## Table of Contents
- [VigiloAuth](#vigiloauth)
	- [Table of Contents](#table-of-contents)
	- [1. Introduction](#1-introduction)
	- [2. Features](#2-features)
		- [2.1. Currently Implemented](#21-currently-implemented)
		- [2.2. Planned Features](#22-planned-features)
		- [2.3. Open ID Conformance Tests](#23-open-id-conformance-tests)
	- [3. Documentation](#3-documentation)
	- [4. Contributing](#4-contributing)
		- [4.1 How to Contribute](#41-how-to-contribute)
		- [4.2. Commit Standards](#42-commit-standards)
		- [4.3. Commit Types](#43-commit-types)
	- [6. License](#5-license)

---

## 1. Introduction

VigiloAuth is designed to simplify the implementation of OAuth 2.0 and OpenID Connect (OIDC) authentication servers. Whether you need a full-fledged **authentication server**, an **identity server**, or both, VigiloAuth provides compliant endpoints that you can easily integrate into your application without writing any complex code.

With VigiloAuth, you can quickly set up secure authentication and identity management solutions for your application, allowing users to authenticate and easily manage their identities. VigiloAuth comes pre-configured with common authentication flows and identity management endpoints, saving you time and effort while making sure that your system complies with industry standards.

Whether you are building a simple app or a complex enterprise system, **VigiloAuth** provides a solid foundation for handling authentication and identity management with minimal effort.

---

## 2. Features

### 2.1. Currently Implemented
- ✅ **User Registration**
- ✅ **User Email Verification**
- ✅ **Basic User Authentication**
- ✅ **OAuth User Authentication**
- ✅ **Authorization Code Flow**
- ✅ **Authorization Code Flow With PKCE**
- ✅ **Resource Owner Password Credentials Flow**
- ✅ **Client Credentials Flow**
- ✅ **Dynamic Client Registration**
- ✅ **Audit Logging**
- ✅ **Docker Server Instance**
- ✅ **Token Refresh**
- ✅ **Token Introspection**
- ✅ **Token Revocation**
- ✅ **OIDC UserInfo Endpoint**
- ✅ **OIDC Discovery Endpoint**
- ✅ **OIDC JSON Web Key Set Endpoint**
- ✅ **In Memory Storage**

### 2.2. Planned Features

- 🛠️ **Realm Support**
- 🛠️ **Phone Number Verification**
- 🛠️ **Password Recovery**
- 🛠️ **User Profile Management**
- 🛠️ **Role-Based Access Control (RBAC)**
- 🛠️ **Scope-Based Access Control**
- 🛠️ **User Consent Management**
- 🛠️ **Time-Based OTP Authentication**
- 🛠️ **Backup Recovery Codes**
- 🛠️ **Implicit Grant Flow**
- 🛠️ **OIDC Hybrid Flow**
- 🛠️ **Device Authorization Grant**
- 🛠️ **Back Channel Authentication Flow**
- 🛠️ **Social Login Integration Hooks**
- 🛠️ **Dynamic Database Configuration**
- 🛠️ **UI for User Authentication**

---

### 2.3. Open ID Conformance Tests

You can find the list of our currently passing conformance tests [here](https://www.certification.openid.net/plan-detail.html?public=true&plan=ZbxeUWhH8Vldh).

---

## 3. Documentation

Comprehensive documentation is available in the [User Guide](./docs/user_guide/README.md).
- [Configuration Guide](./docs/user_guide/configuration/configuration_guide.md)
- [API Endpoints](./docs/user_guide/identity/README.md)

---

## 4. Contributing

We welcome contributions to improve VigiloAuth! Follow the steps below to ensure a smooth contribution process.

>_If you're a first-time contributor, check out our [Good First Issues](https://github.com/vigiloauth/vigilo/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22)._

### 4.1. Reporting Security Vulnerabilities

If you have found a security vulnerability, please follow our [instructions](./SECURITY.md) on how to properly report it.

### 4.2. How to Contribute

1. **Fork the Repository**: Create your own fork on GitHub.
2. **Clone Your Fork**: Clone it to your local development environment.
3. **Create a Branch**: Create a new branch from `master` (e.g., `feature/my-feature`).
4. **Make Your Changes**: Implement your changes in alignment with project goals.
5. **Write Tests**: Add or update tests to cover your changes.
6. **Commit Your Changes**: Use **Conventional Commits** (see below).
7. **Push Your Changes**: Push your branch to your GitHub fork.
8. **Open a Pull Request**: Submit a PR to the main repository and clearly describe your changes.

### 4.3. Commit Standards

We follow the **_Conventional Commit_** standards to ensure clear and meaningful commit messages. Use the format:
```azure
<type>[optional scope]: <description>
[optional body]
[optional footer(s)]
```

### 4.4. Commit Types

- `breaking`: Introduce a breaking change that may require users to modify their code or dependencies.
- `feat`: Add a new feature that enhances the functionality of the project.
- `fix`: Apply a bug fix that resolves an issue without affecting functionality.
- `task`: Add or modify internal functionality that supports the codebase but doesn't introduce a new feature or fix a bug (e.g., utility methods, service logic, or internal improvements).
- `docs`: Update documentation, such as fixing typos or adding new information.
- `style`: Changes that don’t affect the code’s behavior, like formatting or code style adjustments.
- `refactor`: Refactor code without adding features or fixing bugs.
- `test`: Add or modify tests.
- `chore`: Miscellaneous changes like updates to build tools or dependencies.

For more information about contributing, please read our [contribution guide](./docs/contributing/README.md)

---

## 5. Quickstart Example

To get started with VigiloAuth, follow this minimal example:

**1. Create a `vigilo.yaml` configuration file**
```yaml
log_level: debug

server_config:
  port: 8080
  session_cookie_name: vigilo-session
  domain: auth.example.com
  force_https: true
  read_timeout: 30
  write_timeout: 30
```

**2. Create a `.env` file for secrets**
```yaml
SMTP_USERNAME=your_smtp_user
SMTP_FROM_ADDRESS=auth@yourdomain.com
SMTP_PASSWORD=your_smtp_password
TOKEN_ISSUER=auth.yourdomain.com
TOKEN_PRIVATE_KEY=base64_encoded_private_key
TOKEN_PUBLIC_KEY=base64_encoded_public_key
```

**3. Create a `docker-compose.yaml` file**
```yaml
version: '3.9'
services:
  vigilo-auth:
    image: vigiloauth/server:latest
    container_name: vigilo-auth
    ports:
      - "8080:8080"
    volumes:
      - ./vigilo.yaml:/app/vigilo.yaml
    environment:
      VIGILO_CONFIG_PATH: /app/vigilo.yaml
      SMTP_USERNAME: ${SMTP_USERNAME}
      SMTP_FROM_ADDRESS: ${SMTP_FROM_ADDRESS}
      SMTP_PASSWORD: ${SMTP_PASSWORD}
      TOKEN_ISSUER: ${TOKEN_ISSUER}
      TOKEN_PRIVATE_KEY: ${TOKEN_PRIVATE_KEY}
      TOKEN_PUBLIC_KEY: ${TOKEN_PUBLIC_KEY}
```

**4. Run the server**
```bash
docker-compose up
```

>For the full configuration guide and how to include the Admin-UI, refer to the [User Guide](./docs/user_guide/configuration/docker.md)

---

## 6. License

Copyright 2024 Olivier Pimparé-Charbonneau

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
