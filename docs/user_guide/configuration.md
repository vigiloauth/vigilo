# Configuration Guide
## 1. Overview
**VigiloAuth** allows you to customize the password policy settings to meet your application's security requirements. This guide walks you through configuring the password complexity and length requirements using the `PasswordConfiguration` struct.

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

## 4. Validation and Enforcement
The configured password policy will automatically validate and enforce the rules during user registration and password updates. If a password does not meet the configured requirements, an error will be returned.

## 5. Troubleshooting
### Common Issues
- **Password Too Short:** Ensure the SetMinimumLength value is at least 8. 
- **Singleton Behavior:** Changes made to the password configuration persist globally for the application's lifecycle.

