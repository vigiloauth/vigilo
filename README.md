# Vigilo
**Vigilo** is an open-source Go library that allows developers to easily create their own OAuth-based authentication servers. It provides a set of tools for managing client registrations, handling authentication flows, and storing client credentials securely. Vigilo is designed to be flexible, supporting a variety of grant types and allowing users to set up secure and customizable auth servers.

## Contributing
We welcome contributions to improve Vigilo! To maintain clarity and consistency in the commit history, we follow semantic commit messages. Please adhere to the following guidelines for all commits:

### Commit Message Format:
Each commit message should have the following format:
```azure
<type>(scope): <description>
```
- **type:** Specifies the type of change
- **scope:** A brief description of the part of the code affected (optional but recommended). 
- **description:** A short summary of the changes.

#### Types
- **feat:** A new feature. 
- **fix:** A bug fix. 
- **docs:** Documentation-only changes. 
- **style:** Changes that do not affect the meaning of the code (e.g., whitespace, formatting). 
- **refactor:** A code change that neither fixes a bug nor adds a feature. 
- **perf:** A code change that improves performance. 
- **test:** Adding missing tests or correcting existing tests. 
- **chore:** Changes to the build process or auxiliary tools and libraries.

#### Examples
- **feat(client):** add client registration method 
- **fix(database):** resolve issue with nil pointer in mock database 
- **docs(readme):** add installation instructions 
- **chore(deps):** update dependencies

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.


