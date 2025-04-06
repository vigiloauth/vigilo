# Installation Steps

## Table of Contents
1. [Add VigiloAuth to Your Project](#1-add-vigiloauth-to-your-project)
2. [Import the Library](#2-import-the-library)
3. [Basic Setup Example](#3-basic-setup-example)
4. [Testing the Setup](#4-testing-the-setup)
5. [Troubleshooting](#5-troubleshooting)

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

Here’s a minimal example of how to integrate **VigiloAuth** identity endpoints into your application:

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
go run main.go
```

Your identity server will be available at `http://localhost:8080/identity`.

---

## 4. Testing the Setup

To verify that the server is running correctly, you can:

1. Open your browser and navigate to `http://localhost:8080/identity`.
2. Use a tool like `curl` or Postman to test the `/identity` endpoint:
   ```
   curl -X GET http://localhost:8080/identity/health
   ```
   You should receive a response indicating that the server is running.

---

## 5. Troubleshooting

### Missing Dependencies
- Run `go mod tidy` to resolve any dependency issues.

### Port Conflicts
- Verify that the port specified in your `.env` file or the default `8080` is not in use by another application.

### Go Version Compatibility
- Ensure you are using Go 1.18 or higher. Run `go version` to check your installed version.

### Firewall or Network Restrictions
- Ensure that your firewall or network settings allow traffic on the specified port.

---

### Next Steps

After setting up **VigiloAuth**, refer to the [Identity API Endpoints documentation](endpoints/identity/README.md) to learn how to interact with the identity server.