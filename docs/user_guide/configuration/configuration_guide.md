# Configuration Guide

## Table of Contents
- [Configuration Guide](#configuration-guide)
  - [Table of Contents](#table-of-contents)
  - [1. Overview](#1-overview)
  - [2. VigiloAuth Server Configuration](#2-vigiloauth-server-configuration)
  - [3. Token Configuration](#3-token-configuration)
  - [4. Login Configuration](#4-login-configuration)
  - [5. Password Configuration](#5-password-configuration)

---

## 1. Overview

**VigiloAuth** allows you to customize various settings to align with your application's security requirements. Whether it's enforcing certain password policies or token durations, **VigiloAuth** has you covered. Our configurations are used across the library as singletons, making it easy for you to apply your settings

For more details and examples on how to use each configuration based on if you are using our library version or standalone docker instance, refer to the following guides
- [Library Examples](./library.md)
- [Docker Examples](./docker.md)

---

## 2. VigiloAuth Server Configuration

The `VigiloIdentityServer` can be configured using various options to suit your needs. Below are the available configuration options that we offer and their default values, if applicable.

| **Configuration Option**          | **Description**                                         | **Default Value**          |
|-----------------------------------|---------------------------------------------------------|----------------------------|
| **SSL Cert File Path**            | Path to the SSL Certificate when using HTTPS.           | N/A                         |
| **Key File Path**                 | Path to the SSL Key file when using HTTPS.              | N/A                         |
| **Base URL**                      | Base URL that the endpoints will be available on.       | N/A                         |
| **Session Cookie Name**           | The name of the session cookie.                         | `vigilo-auth-session-cookie`|
| **Force HTTPS**                   | Whether to force HTTPS connections.                     | `false`                     |
| **Port**                          | The port number the server listens to.                  | `8443`                      |
| **Requests Per Minute**           | The maximum requests allowed per minute.                | `100`                       |
| **Read Timeout**                  | Read timeout duration for HTTP requests in seconds.     | `15 seconds`                |
| **Write Timeout**                 | Write timeout duration for HTTP requests in seconds.    | `15 seconds`                |
| **Authorization Code Duration**   | The duration of the authorization code in minutes.      | `10 minutes`                |


---

## 3. Token Configuration
| **Configuration Option**          | **Description**                                          | **Default Value**               |
|-----------------------------------|----------------------------------------------------------|---------------------------------|
| **Secret Key**                    | Secret key used for signing and verifying tokens.        | `fallback_secure_default_key`   |
| **Expiration Time**               | Token expiration time in hours.                          | `24 hours`                      |
| **Signing Method**                | Signing Method used for tokens.                          | `HS256`                         |
| **Access Token Duration**         | Access token duration in minutes.                        | `30 minutes`                    |
| **Refresh Token Duration**        | Refresh token duration in minutes.                       | `1440==minutes`                  |

___

## 4. Login Configuration
| **Configuration Option**          | **Description**                                                     | **Default Value**    |
|-----------------------------------|---------------------------------------------------------------------|----------------------|
| **Max Failed Attempts**           | Maximum number of failed login attempts allowed.                    | `5`                  |
| **Delay**                         | Delay duration after exceeding max failed attempts in milliseconds. | `500 ms`             |

---

## 5. Password Configuration
| **Configuration Option**          | **Description**                                       | **Default Value**    |
|-----------------------------------|-------------------------------------------------------|----------------------|
| **Require Uppercase**             | Wether or not uppercase letters are required.         | `false`              |
| **Require Number**                | Wether or not numbers are required.                   | `false`              |
| **Require Symbol**                | Wether or not symbols are required.                   | `false`              |
| **Minimum Length**                | Minium required password length.                      | `5`                  |
