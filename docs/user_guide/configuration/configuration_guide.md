# Configuration Guide

## Table of Contents
- [Configuration Guide](#configuration-guide)
  - [Table of Contents](#table-of-contents)
  - [1. Overview](#1-overview)
  - [2. VigiloAuth Server Configuration](#2-vigiloauth-server-configuration)
  - [3. Token Configuration](#3-token-configuration)
  - [4. Login Configuration](#4-login-configuration)
  - [5. Password Configuration](#5-password-configuration)
  - [6. SMTP Configuration](#6-smtp-configuration)
  - [7. Audit Log Configuration](#7-audit-log-configuration)

---

## 1. Overview

**VigiloAuth** allows you to customize various settings to align with your application's security requirements. Whether it's enforcing certain password policies or token durations, **VigiloAuth** has you covered. Our configurations are used across the library as singletons, making it easy for you to apply your settings

For more details and examples on how to the standalone docker instance, refer to the following guide:
- [Docker Examples](./docker.md)

---

## 2. VigiloAuth Server Configuration

The `VigiloIdentityServer` can be configured using various options to suit your needs. Below are the available configuration options that we offer and their default values, if applicable.

| **Configuration Option**          | **Description**                                         | **Default Value**           |
|-----------------------------------|---------------------------------------------------------|-----------------------------|
| **SSL Cert File Path**            | Path to the SSL Certificate when using HTTPS.           | N/A                         |
| **Key File Path**                 | Path to the SSL Key file when using HTTPS.              | N/A                         |
| **Domain**                        | Server's domain.                                        | `localhost`                 |
| **Session Cookie Name**           | The name of the session cookie.                         | `vigilo-auth-session-cookie`|
| **Force HTTPS**                   | Whether to force HTTPS connections.                     | `false`                     |
| **Enable Request Logging**        | Whether to enable request logging or not.               | `true`                      |
| **Port**                          | The port number the server listens to.                  | `8080`                      |
| **Requests Per Minute**           | The maximum requests allowed per minute.                | `100`                       |
| **Read Timeout**                  | Read timeout duration for HTTP requests in seconds.     | `15 seconds`                |
| **Write Timeout**                 | Write timeout duration for HTTP requests in seconds.    | `15 seconds`                |
| **Authorization Code Duration**   | The duration of the authorization code in minutes.      | `10 minutes`                |
| **Request Logging**               | Whether to enable request logging for http requests.    | `true`                      |


---

## 3. Token Configuration
| **Configuration Option**          | **Description**                                          | **Default Value**               |
|-----------------------------------|----------------------------------------------------------|---------------------------------|
| **Expiration Time**               | Token expiration time in hours.                          | `24 hours`                      |
| **Access Token Duration**         | Access token duration in minutes.                        | `30 minutes`                    |
| **Refresh Token Duration**        | Refresh token duration in minutes.                       | `1440==minutes`                 |
| **Token Private Key**             | Private key used to sign tokens (JWTs).                  | N/A                             |
| **Token Public Key**              | Public key used to verify tokens (JWTs).                 | N/A                             |

**What are the Token Private and Public Keys?**  
The **Token Private Key** is used by the VigiloAuth server to cryptographically sign tokens (such as JWTs) that it issues. The **Token Public Key** is used by clients and other services to verify the authenticity of those tokens. This ensures that tokens cannot be tampered with and can be trusted by other systems.

**How do I generate these keys?**  
You can generate an RSA private and public key pair using the `openssl` command-line tool:
```bash
# Generate a 2048-bit private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract the public key from the private key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

- Use the contents of `private_key.pem` as your **Token Private Key**.
- Use the contents of `public_key.pem` as your **Token Public Key**.

**How do I use these keys with VigiloAuth?**  
Set the keys as environment variables in your `.env` file and reference them in your Docker Compose configuration:

**Example `.env` file:**
```env
TOKEN_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B...\n-----END PRIVATE KEY-----"
TOKEN_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B...\n-----END PUBLIC KEY-----"
```

Refer to the Docker configuration [guide](../configuration/docker.md) on how to properly use the values.

**Note:**
At the moment, the token public and private key are not configurable through the Admin UI, but will be in the near future.

___

## 4. Login Configuration
| **Configuration Option**          | **Description**                                                     | **Default Value**    |
|-----------------------------------|---------------------------------------------------------------------|----------------------|
| **Max Failed Attempts**           | Maximum number of failed login attempts allowed.                    | `5`                  |
| **Delay**                         | Delay duration after exceeding max failed attempts in milliseconds. | `500 ms`             |

---

## 5. Password Configuration
| **Configuration Option**          | **Description**                                        | **Default Value**    |
|-----------------------------------|--------------------------------------------------------|----------------------|
| **Require Uppercase**             | Whether or not uppercase letters are required.         | `false`              |
| **Require Number**                | Whether or not numbers are required.                   | `false`              |
| **Require Symbol**                | Whether or not symbols are required.                   | `false`              |
| **Minimum Length**                | Minium required password length.                       | `5`                  |

---

## 6. SMTP Configuration
| **Configuration Option**          | **Description**                                       | **Default Value**      |
|-----------------------------------|-------------------------------------------------------|------------------------|
| **SMTP Username**                 | Your SMTP username.                                   | N/A                    |
| **SMTP Password**                 | Your SMTP password.                                   | N/A                    |
| **From Address**                  | The address to use to send emails from.               | N/A                    |

**Note:** 
If no configuration is provided, email functionality will not be available.
The SMTP credentials (**SMTP_USERNAME**, **SMTP_PASSWORD**, and **SMTP_FROM_ADDRESS**) can be created using any SMTP server you prefer (e.g., Gmail, Outlook, your own email server, etc.).
These values are passed to the VigiloAuth server via environment variables, typically set in your `.env` file and referenced in your Docker Compose configuration.

**Example `.env` file:**
```env
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD=your-smtp-password
SMTP_FROM_ADDRESS=your@email.com
```

Refer to the Docker configuration [guide](../configuration/docker.md) on how to properly use the values.

**Tip:**
For help setting up SMTP with popular providers, see:
- [Gmail SMTP settings](https://support.google.com/mail/answer/7126229?hl=en)  
- [Outlook/Office365 SMTP settings](https://support.microsoft.com/en-us/office/pop-imap-and-smtp-settings-for-outlook-com-d088b986-291d-42b8-9564-9c414e2aa040)

---

## 7. Audit Log Configuration
| **Configuration Option**          | **Description**                                       | **Default Value**      |
|-----------------------------------|-------------------------------------------------------|------------------------|
| **Retention Period**              | How long audit events should stay in the system.      | `90 days`              |