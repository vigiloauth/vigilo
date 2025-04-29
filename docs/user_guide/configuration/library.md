# Library Configuration

## Table of Contents
- [Library Configuration](#library-configuration)
  - [Table of Contents](#table-of-contents)
  - [1. Add VigiloAuth to Your Project](#1-add-vigiloauth-to-your-project)
  - [2. Import the Library](#2-import-the-library)
  - [3. Basic Setup Example](#3-basic-setup-example)
    - [3.1 Configuring The Server](#31-configuring-the-server)
    - [3.2 Token Configuration](#32-token-configuration)
    - [3.3 Login Configuration](#33-login-configuration)
    - [3.4 Password Configuration](#34-password-configuration)
    - [3.5 SMTP Configuration](#35-smtp-configuration)
    - [3.6 Audit Log Configuration](#36-audit-log-configuration)
    - [3.7 Full Example](#36-full-example)
  - [4. When to Use](#4-when-to-use)
  - [5. Next Steps](#5-next-steps)

---

## 1. Add VigiloAuth to Your Project

Run the following command to add **VigiloAuth** to your Go module:
```
go get -u github.com/vigiloauth/vigilo@<latest version>
```
This will download the latest stable release of **VigiloAuth** and add it to your `go.mod` file.

---

## 2. Import the Library

In your Go application, import the necessary modules to start using **VigiloAuth**:
```go
package main

import "github.com/vigiloauth/vigilo/identity/server"
```

---

## 3. Basic Setup Example

Here’s a minimal example of how to integrate **VigiloAuth** into your application:

```go
package main

import (
    "fmt"
    "github.com/go-chi/chi/v5"
    "github.com/vigiloauth/vigilo/identity/server"
    "net/http"
)

func main() {
    // Create a new router
    appRouter := chi.NewRouter()

    // Initialize the VigiloIdentityServer with default configuration
    vigiloIdentityServer := server.NewVigiloIdentityServer()

    // Retrieve the Vigilo Identity router
    vigiloIdentityRouter := vigiloIdentityServer.Router()

    // Mount the VigiloIdentity router to your application's router
    appRouter.Mount("/identity", vigiloIdentityRouter)

    // Start the server
    fmt.Println("Starting server on :8080")
    http.ListenAndServe(":8080", appRouter)
}
```

Save this file as `main.go`, then run the application:
```
go build main.go
go run main.go
```

---

### 3.1 Configuring The Server
Here is an example on how to configure the server to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```go
package main

import (
    // imports remain the same as the previous example
    ...

    // Add the configuration file
    "github.com/vigiloauth/vigilo/identity/config"
)

func main() {
    config.NewServerConfig(
        config.WithBaseURL("/identity"),
        config.WithPort("8080"),
        config.WithCertFilePath("/path/to/cert"),
        config.WithKeyFilePath("/path/to/key"),
        config.WithSessionCookieName("cookie-name"),
        config.WithForceHTTPS(),
        config.WithRequestLogging(true),
        config.WithReadTimeout(time.Duration(15) * time.Second),
        config.WithWriteTimeout(time.Duration(15) * time.Second),
    )

    // remainder of the main stays the same as our basic example.
}
```

---

### 3.2 Token Configuration
Here is an example on how to configure the token functionality to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```go
package main

import (
    // imports remain the same as the previous example
    ...

    // Add the configuration file
    "github.com/vigiloauth/vigilo/identity/config"
)

func main() {
    tokenConfig := config.NewTokenConfig(
        config.WithExpirationTime(time.Duration(2) * time.Hour),
        config.WithAccessTokenDuration(time.Duration(10) * time.Minute),
        config.WithRefreshTokenDuration(time.Duration(1) * 24 * time.Hour),
    )

    // Add the token configuration to the server
    config.NewServerConfig(
        config.WithTokenConfig(tokenConfig),
    )

    // remainder of main stays the same as our basic example.
}
```

---

### 3.3 Login Configuration
Here is an example on how to configure the login functionality to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```go
package main

import (
    // imports remain the same as the previous example
    ...

    // Add the configuration file
    "github.com/vigiloauth/vigilo/identity/config"
)

func main() {
    loginConfig := config.NewLoginConfig(
        config.WithMaxFailedAttempts(10),
        config.WithDelay(time.Duration(600) * time.Millisecond),
    )

    // Add the login configuration to the server
    config.NewServerConfig(
        config.WithLoginConfig(loginConfig),
    )

    // remainder of main stays the same as our basic example.
}
```

---

### 3.4 Password Configuration
Here is an example on how to configure the password requirements to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```go
package main

import (
    // imports remain the same as the previous example
    ...

    // Add the configuration file
    "github.com/vigiloauth/vigilo/identity/config"
)

func main() {
    passwordConfig := config.NewPasswordConfig(
        config.WithUppercase(),
        config.WithNumber(),
        config.WithSymbol(),
        config.WithMinLength(12),
    )

    // Add the password configuration to the server
    config.NewServerConfig(
        config.WithPasswordConfig(passwordConfig),
    )

    // remainder of main stays the same as our basic example.
}
```

---

### 3.5 SMTP Configuration
Here is an example on how to configure the SMTP requirements to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```go
package main

import (
    // imports remain the same as the previous example
    ...

    // Add the configuration file
    "github.com/vigiloauth/vigilo/identity/config"
)

func main() {
    smtpConfig := config.NewSMTPConfig(
        config.WithTLS(),
        config.WithCredentials("username", "password"),
        config.WithFromAddress("vigiloauth@no-reply.com"),
        config.WithEncryption("tls")
    )

    // Add the token configuration to the server
    config.NewServerConfig(
        config.WithSMTPConfig(smtpConfig),
    )

    // remainder of main stays the same as our basic example.
}
```

---

### 3.6 Audit Log Configuration
Here is an example on how to configure the Audit Log requirements to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```go
package main

import (
    // imports remain the same as the previous example
    ...

    // Add the configuration file
    "github.com/vigiloauth/vigilo/identity/config"
)

func main() {
    auditLogConfig := config.NewAuditLogConfig(
        config.WithRetentionPeriod(90 * 24 * time.Hour),
    )

    // Add the token configuration to the server
    config.NewServerConfig(
        config.WithAuditLogConfig(auditLogConfig),
    )

    // remainder of main stays the same as our basic example.
}
```

---

### 3.7 Full Example
```go
package main

import (
    "fmt"
    "github.com/go-chi/chi/v5"
    "github.com/vigiloauth/vigilo/identity/server"
    "net/http"
    "github.com/vigiloauth/vigilo/identity/config"
)

func main() {
    passwordConfig := config.NewPasswordConfig(
        config.WithUppercase(),
        config.WithNumber(),
        config.WithSymbol(),
        config.WithMinLength(12),
    )

    loginConfig := config.NwwLoginConfig(
        config.WithMaxFailedAttempts(10),
        config.WithDelay(time.Duration(600) * time.Millisecond),
    )

    tokenConfig := config.NewTokenConfig(
        config.WithExpirationTime(time.Duration(2) * time.Hour),
        config.WithAccessTokenDuration(time.Duration(10) * time.Minute),
        config.WithRefreshTokenDuration(time.Duration(1) * 24 * time.Hour),
    )

    smtpConfig := config.NewSMTPConfig(
        config.WithTLS(),
        config.WithCredentials("username", "password"),
        config.WithFromAddress("vigiloauth@no-reply.com"),
        config.WithEncryption("tls")
    )

    auditLogConfig := config.NewAuditLogConfig(
        config.WithRetentionPeriod(90 * 24 * time.Hour),
    )

    config.NewServerConfig(
        config.WithBaseURL("/identity"),
        config.WithPort("8080"),
        config.WithCertFilePath("/path/to/cert"),
        config.WithKeyFilePath("/path/to/key"),
        config.WithSessionCookieName("cookie-name"),
        config.WithForceHTTPS(),
        config.WithRequestLogging(true),
        config.WithReadTimeout(time.Duration(15) * time.Second),
        config.WithWriteTimeout(time.Duration(15) * time.Second),
        config.WithPasswordConfig(passwordConfig),
        config.WithLoginConfig(loginConfig),
        config.WithTokenConfig(tokenConfig),
        config.WithSMTPConfig(smtpConfig),
        config.WithAuditLogConfig(auditLogConfig),
    )

    // remainder of main stays the same as our basic example.
}
```

---

## 4. When to Use
The decision to use **VigiloAuth** as code integration depends on your specific needs and the environment in which you are operating. Here's a breakdown of when to use **VigiloAuth** as code integration:
1. **Customization:** You need fine-grained control over the authentication logic and configurations. Integrating the library into your codebase allows you to directly modify and extend its functionality to suit your exact application needs.
2. **Tight Integration:** Your application is already written in Go, and you want the authentication functionality to be deeply integrated with your existing application code.
3. **Avoid External Dependencies:** You prefer not to have the overhead of managing a separate service (e.g., a Docker container) and want everything to run within the same environment.
4. **Development and Testing:** During development, you might want to rapidly iterate on the authentication service without the need to deploy and manage a separate Docker container.

Use code integration if you need flexibility, deeper integration, or want to maintain everything within your application's codebase.

---

## 5. Next Steps
After setting up **VigiloAuth**, refer to the [Identity API Endpoints documentation](endpoints/identity/README.md) to learn how to interact with the identity server.