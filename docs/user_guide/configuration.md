# Configuration Guide

## Table of Contents
- [Configuration Guide](#configuration-guide)
	- [Table of Contents](#table-of-contents)
	- [1. Overview](#1-overview)
	- [2. Server Configuration](#2-server-configuration)
		- [2.1 ForceHTTPS](#21-forcehttps)
		- [2.2 LoginConfig and JWTConfig](#22-loginconfig-and-jwtconfig)
			- [Default Values](#default-values)
		- [2.3 Example Usage](#23-example-usage)
		- [2.4 Default fields](#24-default-fields)
	- [3. Customizing Password Policy](#3-customizing-password-policy)
		- [3.1 Explanation of Methods](#31-explanation-of-methods)
	- [4. Configuring JWT](#4-configuring-jwt)
		- [4.1 Example Configuration](#41-example-configuration)
		- [4.2 Explanation of Fields](#42-explanation-of-fields)
		- [4.3 Default Fields](#43-default-fields)
	- [5. Configuring Login](#5-configuring-login)
		- [5.1 Example Configuration](#51-example-configuration)
		- [5.2 Explanation of Fields](#52-explanation-of-fields)
		- [5.3 Default Fields](#53-default-fields)
	- [6. Handing SSL Certificate Errors in the Frontend](#6-handing-ssl-certificate-errors-in-the-frontend)
	- [7. Validation and Enforcement](#7-validation-and-enforcement)
	- [8. Troubleshooting](#8-troubleshooting)

## 1. Overview
**VigiloAuth** allows you to customize various settings to meet your application's security requirements. This guide walks you through configuring the password complexity and length requirements using the `PasswordConfiguration` struct, as well as configuring the server to enforce HTTPS for secure communication.

## 2. Server Configuration
The `VigiloIdentityServer` can be configured using various options to suit your needs. Below are the available configuration options:

### 2.1 ForceHTTPS
To ensure secure communication, it is recommended to configure your server to use HTTPS. This is done by configuring the `VigiloIdentityServer` with the `ForceHTTPS` option.

### 2.2 LoginConfig and JWTConfig
The `VigiloIdentityServer` uses `LoginConfig` and `JWTConfig` for handling user authentication and token generation. These configurations have default values that will be used if they are not explicitly provided in the constructor.

#### Default Values
- **LoginConfig**: If not provided, the server will use a default configuration for login attempts and user authentication.
- **JWTConfig**: If not provided, the server will use a default configuration for JWT token generation, including a default secret key, expiration time, and signing method.

### 2.3 Example Usage
Here is an example of how to create a `VigiloIdentityServer` with default configurations:

```go
package main

import (
    "github.com/vigiloauth/vigilo/identity/config"
    "github.com/vigiloauth/vigilo/identity/server"
    "time"
)

func main() {
	port := 8080
	certFilePath := "/path/to/cert.pem"
	keyFilePath := "/path/to/key.pem"
	readTimeout := 15 * time.Second
	writeTimeout := 15 8 time.Second
	requestsPerMinute := 100

	serverConfig := NewServerConfig(
		WithPort(port),
		WithCertFilePath(certFilePath),
		WithKeyFilePath(keyFilePath),
		WithReadTimeout(readTimeout),
		WithWriteTimeout(writeTimeout)
		WithMaxRequestsPerMinute(requestsPerMinute)
	)

	vigiloIdentityServer := server.NewVigiloIdentityServer(serverConfig)
}
```
You can also customize these configurations by providing specific options:
``` go
serverConfig := config.NewServerConfig(
    config.WithLoginConfig(customLoginConfig),
    config.WithJWTConfig(customJWTConfig),
)
vigiloIdentityServer := server.NewVigiloIdentityServer(serverConfig)
```
By using these options, you can tailor the server's behavior to match your specific requirements while still benefiting from sensible default values.

### 2.4 Default fields
By default, the server configuration uses the following settings:
- **Port:** 8443
- **ForceHTTPS:** false
- **ReadTimeout:** 15 seconds
- **WriteTimeout:** 15 seconds
- **RequestsPerMinute:** 100

## 3. Customizing Password Policy
To customize the password policy, use the `GetPasswordConfiguration().ConfigurePasswordPolicy(options)` singleton to access the configuration instance and update the settings.
```go
package main

import "github.com/vigiloauth/vigilo/config"

func main() {
	// Get the password configuration instance.
	passwordConfig := GetPasswordConfiguration()

	// Customize the settings.
	passwordConfig.ConfigurePasswordPolicy(
		WithUppercase(),
		WithNumber(),
		WithSymbol(),
		WithMinLength(12),
	)
}
```

### 3.1 Explanation of Methods
1. `WithUppercase()` Enables requiring at least one uppercase letter in passwords. 
2. `WithNumber()` Enables requiring at least one numeric digit in passwords. 
3. `WithSymbol()` Enables requiring at least one special character in passwords. 
4. `WithMinLength(int)` Sets the minimum password length. The value must be at least 8 characters or more for security purposes.

## 4. Configuring JWT
To configure JWT settings, use the `JWTConfig` struct to set the secret, expiration time, and signing method.

### 4.1 Example Configuration
```go
package main

import (
    "github.com/vigiloauth/vigilo/identity/config"
    "github.com/vigiloauth/vigilo/identity/server"
    "time"
)

func main() {
	secret := "you_secret"
	expirationTime := 15 * time.Minute
	signingMethod := jwt.SigningMethodHS256

	jwtConfig := NewJWTConfig(
		WithSecret(secret),
		WithExpirationTime(expirationTime),
		WithSigningMethod(signingMethod),
	)

	serverConfig := NewServerConfig(
		WithJWTConfig(jwtConfig),
	)
}
```
### 4.2 Explanation of Fields
1. `WithSecret(string)`: The secret key used to sign the JWT tokens. This should be kept secure and not hard-coded in production.
2. `WithExpirationTime(time.Duration)`: The duration for which the JTW token is valid.
3. `WithSigningMethod(jwt.SigningMethodHS256)`: The signing method used to sign the JWT tokens. Common methods include `jwt.SigningMethodHS256`.

### 4.3 Default Fields
If no custom JWT configuration is provided, the following default values are used:
1. `Secret`: "fallback_secure_default_key" (for developmental/testing purposes only)
2. `ExpirationTime`: 24 hours
3. `SigningMethod`: `jwt.SigningMethodHS256`

## 5. Configuring Login 
To configure login details for your application, use the `LoginConfig` struct to set the maximum login attempts a user can have and the artificial delay to normalize response times for login attempts.

### 5.1 Example Configuration
```go
package main

import (
    "github.com/vigiloauth/vigilo/identity/config"
    "github.com/vigiloauth/vigilo/identity/server"
    "time"
)

func main() {
	maxFailedAttempts := 5
	delay := 500 * time.Millisecond

	loginConfig := NewLoginConfig(
		WithMaxFailedAttempts(maxFailedAttempts),
		WithDelay(delay),
	)
}
```
### 5.2 Explanation of Fields
- `WithMaxFailedAttempts(int)`: Configures the maximum failed attempts a user can have when attempting to login.
- `WithDelay(time.Duration)`: Applies an artificial delay during the login process to mitigate automated brute-force password cracking attempts.

### 5.3 Default Fields
If no custom login configuration is provided, the following default values are used:
1. `MaxFailedAttempts(int)`: 5
2. `Delay()`: 500 * time.Millisecond

## 6. Handing SSL Certificate Errors in the Frontend
Frontend applications should handle SSL certificate errors gracefully. Here are some recommended guidelines:
- **Notify Users:** Display clear messages to users if their connection is not secure.
- **Fallback Options:** Provide instructions for users to proceed if they trust the connection.

## 7. Validation and Enforcement
The configured password policy will automatically validate and enforce the rules during user registration and password updates. If a password does not meet the configured requirements, a detailed error will be returned.

## 8. Troubleshooting
**Common Issues**
- **Password Too Short:** Ensure the `WithMinLength(int)` value is at least 8.
- **Singleton Behavior:** Changes made to the password configuration persist globally for the applications lifecycle.
