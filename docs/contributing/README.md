# Welcome to the VigiloAuth Contribution Guide 👋

Thank you for your interest in contributing to **VigiloAuth**, an open-source authentication server library. This guide will help you get started quickly and contribute effectively.

---

## Table of Contents
- [Welcome to the VigiloAuth Contribution Guide 👋](#welcome-to-the-vigiloauth-contribution-guide-)
  - [Table of Contents](#table-of-contents)
  - [1. How to Contribute](#1-how-to-contribute)
  - [2 Commit Standards](#2-commit-standards)
    - [2.1 Commit Types](#21-commit-types)
    - [2.2 Manual Testing](#22-manual-testing)
  - [3. Development Environment Setup](#3-development-environment-setup)
    - [3.1 Node.js Version](#31-nodejs-version)
      - [Check your Node version:](#check-your-node-version)
    - [3.2 Installing `nvm` (Node Version Manager)](#32-installing-nvm-node-version-manager)
    - [3.3 Install \& Use the Correct Node Version](#33-install--use-the-correct-node-version)
  - [4. License](#4-license)

---

## 1. How to Contribute

1. **Fork the Repository**: Create your own fork on GitHub.
2. **Clone Your Fork**: Clone it to your local development environment.
3. **Create a Branch**: Create a new branch from `main` (e.g., `feature/my-feature`).
4. **Make Your Changes**: Implement your changes in alignment with project goals.
5. **Write Tests**: Add or update tests to cover your changes.
6. **Commit Your Changes**: Use **Conventional Commits** (see below).
7. **Push Your Changes**: Push your branch to your GitHub fork.
8. **Open a Pull Request**: Submit a PR to the main repository and clearly describe your changes.

_If you're a first-time contributor, check out our [Good First Issues](https://github.com/vigiloauth/vigilo/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22)._

___

## 2 Commit Standards

We follow the **_Conventional Commit_** standards to ensure clear and meaningful commit messages. Use the format:
```azure
<type>[optional scope]: <description>
[optional body]
[optional footer(s)]
```

### 2.1 Commit Types

- `breaking`: Introduce a breaking change that may require users to modify their code or dependencies.
- `feat`: Add a new feature that enhances the functionality of the project.
- `fix`: Apply a bug fix that resolves an issue without affecting functionality.
- `task`: Add or modify internal functionality that supports the codebase but doesn't introduce a new feature or fix a bug (e.g., utility methods, service logic, or internal improvements).
- `chore`: Miscellaneous or updates that aren't features or fixes (e.g., updating build tools, dependencies, or configuration files).
- `docs`: Modify documentation, such as fixing typos or adding new content.
- `style`: Apply code style or formatting changes that do not affect behavior.
- `refactor`: Restructure existing code without changing its external behavior.
- `test`: Add or modify tests without affecting functionality.


### 2.2 Manual Testing

To facilitate the process of manually testing changes, we provide a script to push a Docker container for manual testing purposes. To run the script, navigate to the `scripts` directory from your terminal and simply run:
```bash
./push_docker_dev.sh
```

---

## 3. Development Environment Setup

If you are working on the frontend, make sure you have the correct version of Node.js.

### 3.1 Node.js Version

This project uses **Vite**, which requires **Node.js v18 or later**.

#### Check your Node version:
```bash
node -v
```

If it is below `v18`, follow the steps below to upgrade using `nvm`.

### 3.2 Installing `nvm` (Node Version Manager)
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
```

Then restart your terminal or run the following command:
```
source ~/.zshrc  # or ~/.bashrc, depending on your shell
```

### 3.3 Install & Use the Correct Node Version
```bash
nvm install 20
nvm use 20
```

You should now be on a compatible version:
```bash
node -v  # should show v20.x.x
```

Then run the project as usual:
```bash
npm install
npm run dev
```

---

## 4. License

Copyright 2024 Olivier Pimparé-Charbonneau

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.