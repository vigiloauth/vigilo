# Configuration Guide

## Table of Contents
1. [Overview](#1-overview)
2. [Default Settings](#2-default-settings)
3. [Customizing Password Policy](#3-customizing-password-policy)
    - [Explanation of Methods](#31-explanation-of-methods)
4. [Configuring HTTPS](#4-configuring-https)
    - [Configuring HTTPS](#41-configuring-https)
	- [Default Fields](#42-default-fields)
5. [Configuring JWT](#5-configuring-jwt)
    - [Example Configuration](#51-example-configuration)
    - [Explanation of Fields](#52-explanation-of-fields)
    - [Default Fields](#53-default-fields)
6. [Configuring Login Attempts](#6-configuring-login-attempts)
	- [Example Configuration](#61-example-configuration)
	- [Default Fields](#62-default-fields)
7. [Handling SSL Certificate Errors in the Frontend](#7-handling-ssl-certificate-errors-in-the-frontend)
8. [Validation and Enforcement](#8-validation-and-enforcement)
9. [Troubleshooting](#9-troubleshooting)

## 1. Overview
**VigiloAuth** allows you to customize various settings to meet your application's security requirements. This guide walks you through configuring the password complexity and length requirements using the `PasswordConfiguration` struct, as well as configuring the server to enforce HTTPS for secure communication.

## 2. Default Settings
By default, the password policy is initialized with the following settings:
- **Uppercase Letters:** Not required 
- **Numbers:** Not required 
- **Symbols:** Not required 
- **Minimum Length:** 8 characters

The server configuration includes a default JWT secret for development/testing purposes. These settings provide a basic level of security but can be customized as needed.

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
### 4.2 Default fields
If no custom Login or JWT configurations are provided, the application will use the default login and JWT configuration.

## 5. Configuring JWT
To configure JWT settings, use the `JWTConfig` struct to set the secret, exipration time, and signing method.

### 5.1 Example Configuration
```go
package main

import (
    "github.com/vigiloauth/vigilo/identity/config"
    "github.com/vigiloauth/vigilo/identity/server"
    "time"
)

func main() {
	jwtConfig := config.NewCustomJWTConfig("your_jwt_secret", 24 * time.Hour, jwt.SigningMethodHS256)
	serverConfig := config.NewServerConfig(8443, &certFilePath, &keyFilePath, true, 15*time Second, 15*time.Second, jwtConfig)
}
```
### 5.2 Explanation of Fields
1. `Secret` (string): The secret key used to sign the JWT tokens. This should be kept secure and not hard-coded in production.
2. `ExpirationTime` (time.Duration): The duration for which the JTW token is valid.
3. `SigningMethod` (jwt.SigningMethod): The signing method used to sign the JWT tokens. Common methods include `jwt.SigningMethodHS256`.

### 5.3 Default Fields
If no custom JWT configuration is provided, the following default valures are used:
1. `Secret`: "default_secret_key" (for developmental/testing purposes only)
2. `ExpirationTime`: 24 hours
3. `SigningMethod`: `jwt.SigningMethodHS256`

## 6. Configuring Login Attempts
To configure login attempts for your application, use the `LoginConfig` struct to set the maximum login attempts a user can have.

### 6.1 Example Configuration
```go
package main

import (
    "github.com/vigiloauth/vigilo/identity/config"
    "github.com/vigiloauth/vigilo/identity/server"
    "time"
)

func main() {
	maxLoginAttempts := 5
	loginConfig := config.NewCustomLoginConfig(maxLoginAttempts)
	jwtConfig := config.NewCustomJWTConfig("your_jwt_secret", 24 * time.Hour, jwt.SigningMethodHS256)
	serverConfig := config.NewServerConfig(8443, &certFilePath, &keyFilePath, true, 15*time Second, 15*time.Second, jwtConfig, loginConfig)
}
```

### 6.2 Default Fields
If no custom login configuration is provided, the following default values are used:
1. `MaxFailedAttempts`: 5

## 7. Handing SSL Certificate Errors in the Frontent
Frontend applications should handle SSL certificate errors gracefully. Here are some recommended guidelines:
- **Notify Users:** Display clear messages to users if their connection is not secure.
- **Fallback Options:** Provide instructions for users to proceed if they trust the connection.

## 8. Validation and Enforcement
The configured password policy will automatically validate and enforce the rules during user registration and password updates. If a password does not meet the configured requirements, a detailed error will be returned.

## 9. Troubleshooting
**Common Issues**
- **Password Too Short:** Ensure the `SetMinimumLength` value is at least 8.
- **Singleton Behavior:** Changes made to the password configuration persist globally for the applications lifecycle.
