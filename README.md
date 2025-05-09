# VigiloAuth

![Docker Release](https://img.shields.io/github/v/release/vigiloauth/vigilo?label=latest%20release)
![Github Repo Starts](https://img.shields.io/github/stars/vigiloauth/vigilo?style=flat)

## Table of Contents
- [VigiloAuth](#vigiloauth)
	- [Table of Contents](#table-of-contents)
	- [1. Introduction](#1-introduction)
	- [2. Features](#2-features)
		- [2.1 Currently Implemented](#21-currently-implemented)
		- [2.2 Planned Features](#22-planned-features)
		- [2.3 Open ID Conformance Tests](#23-open-id-conformance-tests)
	- [3. Documentation](#3-documentation)
	- [4. Contributing](#4-contributing)
		- [4.1 How to Contribute](#41-how-to-contribute)
		- [4.2 Commit Standards](#42-commit-standards)
		- [5.3 Commit Types](#53-commit-types)
	- [5. License](#5-license)

## 1. Introduction
⚠️ **Note:** VigiloAuth is currently in development and not yet feature-complete. Some functionalities are still being implemented, and APIs may change in future releases.

VigiloAuth is designed to simplify the implementation of OAuth 2.0 and OpenID Connect (OIDC) authentication servers. Whether you need a full-fledged **authentication server**, an **identity server**, or both, Vigilo provides compliant endpoints that you can easily integrate into your application without writing complex authentication code.

With VigiloAuth, you can quickly set up secure authentication and identity management solutions for you application, allowing users to authenticate and easily manage their identities. The library comes pre-configured with common authentication flows and identity management endpoints, saving you time and effort while making sure that your system complies with industry standards

Whether you are building a simple app or a complex enterprise system, **VigiloAuth** provides a solid foundation for handling authentication and identity management with minimal effort.

## 2. Features
### 2.1 Currently Implemented
- ✅ **User Registration**
- ✅ **Basic User Authentication**
- ✅ **OAuth User Authentication**
- ✅ **User Email Verification**
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

### 2.2 Planned Features
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

### 2.3 Open ID Conformance Tests
You can find the list of our currently passing conformance tests [here](./oidc_conformance_tests.md).

## 3. Documentation
Comprehensive documentation is available in the [User Guide](./docs/user_guide/README.md).
- [Configuration Guide](./docs/user_guide/configuration/configuration_guide.md)
- [Identity API Endpoints](./docs/user_guide/identity/README.md)

## 4. Contributing
We welcome contributions to improve VigiloAuth! Follow the steps below to ensure a smooth contribution process.

### 4.1 How to Contribute
1. **Fork the Repository:** Create your own fork of the repository on GitHub.
2. **Clone Your Fork:** Clone your fork locally.
3. **Create a Branch:** Create a feature or a bug fix branch from master.
4. **Make Your Changes:** Implement your changes and ensure they align with the project goals.
5. **Write Tests:** Add or update tests to validate your changes.
6. **Commit Your Changes:** Use **_Conventional Commits_** for all commit messages (see standards below).
7. **Push Your Changes:** Push your branch to your forked repository.
8. **Open a Pull Request (PR):** Submit a PR to the main repository with a clear description of your changes.

### 4.2 Commit Standards
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
- `docs`: Update documentation, such as fixing typos or adding new information. 
- `style`: Changes that don’t affect the code’s behavior, like formatting or code style adjustments. 
- `refactor`: Refactor code without adding features or fixing bugs. 
- `test`: Add or modify tests. 
- `chore`: Miscellaneous changes like updates to build tools or dependencies.

## 5. License
Copyright 2024 Olivier Pimparé-Charbonneau, Zachary Sexton

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
