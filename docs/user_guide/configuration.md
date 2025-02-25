# Configuration Guide
## 1. Overview
**VigiloAuth** allows you to customize various settings to meet your application's security requirements. This guide walks you through configuring the password complexity and length requirements using the `PasswordConfiguration` struct, as well as configuring the server to enforce HTTPS for secure communication.

## 2. Default Settings
By default, the password policy is initialized with the following settings:
- **Uppercase Letters:** Not required 
- **Numbers:** Not required 
- **Symbols:** Not required 
- **Minimum Length:** 8 characters

These settings provide a basic level of security but can be customized as needed.

## 3. Customizing Password Policy
To customize the password policy, use the `GetPasswordConfiguration` singleton to access the configuration instance and update the settings.
```go
package main

import "github.com/vigiloauth/vigilo/config"

func main() {
	// Get the password configuration instance.
	passwordConfig := config.GetPasswordConfiguration()
	
	// Customize the settings.
	passwordConfig.
		SetRequireUppercase(true).
		SetRequireNumber(true).
		SetRequireSymbol(true).
		SetMinimumLength(12).
		Build()
}
```

### 3.1 Explanation of Methods
1. `SetRequireUppercase(bool)` Enables or disables requiring at least one uppercase letter in passwords. 
2. `SetRequireNumber(bool)` Enables or disables requiring at least one numeric digit in passwords. 
3. `SetRequireSymbol(bool)` Enables or disables requiring at least one special character in passwords. 
4. `SetMinimumLength(int)` Sets the minimum password length. The value must be at least 8 characters or more for security purposes.

## 4. Configuring HTTPS
To ensure secure transmission, **VigiloAuth** enforces HTTPS and redirects any HTTP requests to HTTPS. This is done by configuring the `VigiloIdentityServer` with the `ForceHTTPS` option.

### 4.1 Configuring HTTPS
1. **Obtain a valid SSL/TLS certificate:** You can obtain a certificate from a trusted Certificate Authority (CA) or use a self-sifned certificate for development purposes.
2. **Configure the server:** Provide the certificate and key file paths in the `ServerConfig`.

By default, the server configuration uses the following settings:
- **Port:** 8443
- **ForceHTTPS:** false
- **ReadTimeout:** 15 seconds
- **WriteTimeout:** 15 seconds

```go
package main

import (
    "github.com/vigiloauth/vigilo/identity/config"
    "github.com/vigiloauth/vigilo/identity/server"
    "time"
)

func main() {
	certFilePath := "/path/to/cert.pem"
	keyFilePath := "/path/to/key.pem"
    serverConfig := config.NewServerConfig(8443, &certFilePath, &keyFilePath, true, 15*time.Second, 15*time.Second)

	vigiloIdentityServer := server.NewVigiloIdentityServer(serverConfig)
	// Start the server (example)
    // http.ListenAndServeTLS(":8443", certFilePath, keyFilePath, vigiloIdentityServer.Router())
}
```
### 4.2 Handling SSL Certificate Errors in the Frontent
Frontend applications should handle SSL certificate errors gracefully. Here are some recommended guidelines:
- **Notify Users:** Display a clear message to users if their connection is not secure.
- **Fallback Options:** Provide instructions for users to proceed if they trust the connection.

## 5. Validation and Enforcement
The configured password policy will automatically validate and enforce the rules during user registration and password updates. If a password does not meet the configured requirements, a detailed error will be returned.

## 6. Troubleshooting
**Common Issues**
- **Password Too Short:** Ensure the `SetMinimumLength` value is at least 8.
- **Singleton Behavior:** Changes made to the password configuration persist globally for the applications lifecycle.
