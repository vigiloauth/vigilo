# Installation Steps
### 1. Add VigiloAuth to your project
Run the following command to add **VigiloAuth** to your go module:
```
go get -u github.com/vigiloauth/vigilo@v1.0.3
```
This will download the latest stable release of VigiloAuth and add it to your `go.mod` file.

### 2. Import the library
In your Go application, import the necessary modules to start using **VigiloAuth**:
```go
package main

import "github.com/vigiloauth/vigilo/identity/server"
```

### 3. Basic Setup Example
Here’s a minimal example of how to integrate **VigiloAuth** identity endpoints into your application:
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
	
	// Initialize the VigiloIdentityServer 
	vigiloIdentityServer := server.NewVigiloIdentityServer()
	
	// Retrieve the Vigilo Identity router.
	vigiloIdentityRouter := vigiloIdentityServer.Router()
	
	// Mount the VigiloIdentity router to your application's router.
	appRouter.Mount("/identity", vigiloIdentityRouter)
	
	fmt.Println("Starting server on :8080")
	http.ListenAndServe(":8080", appRouter)
}
```
Save this file as `main.go`, then run the application:
```
go run main.go
```
Your identity server will be available at `http://localhost:8080/identity`.

### Next Steps
After setting up VigiloAuth, refer to the [Identity API Endpoints documentation](endpoints/identity/README.md) to learn how to interact with the identity server.

### 4. Troubleshooting
- **Missing Dependencies:** Ensure you’ve run go mod tidy to resolve any dependency issues. 
- **Port Conflicts:** Verify that the port specified in your `.env` file or the default 8080 is not in use.


