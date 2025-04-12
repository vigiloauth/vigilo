# Docker Instance Configuration

## Table of Contents
- [Docker Instance Configuration](#docker-instance-configuration)
  - [Table of Contents](#table-of-contents)
  - [1. Add VigiloAuth to Your Project](#1-add-vigiloauth-to-your-project)
  - [2. Import the Library](#2-import-the-library)
  - [3. Basic Setup Example](#3-basic-setup-example)
    - [3.1 Configuring The Server](#31-configuring-the-server)
    - [3.2 Token Configuration](#32-token-configuration)
    - [3.3 Login Configuration](#33-login-configuration)
    - [3.4 Password Configuration](#34-password-configuration)
  - [4. When to Use](#4-when-to-use)
  - [5. Next Steps](#5-next-steps)

---

## 1. Add VigiloAuth to Your Project

To add **VigiloAuth** to your project, simply create a `yaml` configuration file, and your desired configuration settings.

---

## 2. Import the Library

In your `docker-compose.yaml` file, add **VigiloAuth** as a service:
```yaml
services:
    vigilo-auth:
        image: vigiloauth/server:latest
        container_name: vigilo-auth
        ports:
         - "8080:8080"
        volumes:
         - ./<path to your yaml config>:/app/vigilo.yaml
        environment:
         VIGILO_CONFIG_PATH: /app/vigilo.yaml
```

---

## 3. Basic Setup Example

Here’s a minimal example of how to integrate **VigiloAuth** into your application:

```yaml
log_level: debug # default log level is INFO

server_config:
  port: 8080
  session_cookie_name: test-session-cookie
  base_url: /identity
  force_https: true
  read_timeout: 30 # in seconds
  write_timeout: 30 # in seconds
  authorization_code_duration: 30 # in minutes

```

After adding the configuration file to your `docker-compose.yaml` file, simply run the following command in your terminal:
```
docker-compose up
```

---

### 3.1 Configuring The Server
Here is an example on how to configure the server to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```yaml
log_level: debug

server_config:
  port: 8080
  session_cookie_name: test-session-cookie
  base_url: /identity
  force_https: true
  read_timeout: 30
  write_timeout: 30
  authorization_code_duration: 30
```

---

### 3.2 Token Configuration
Here is an example on how to configure the tokens to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```yaml
token_config:
  secret_key: secret
  expiration_time: 30 # in minutes
  access_token_duration: 30 # in minutes
  refresh_token_duration: 2 # in days
```

---

### 3.3 Login Configuration
Here is an example on how to configure the login functionality to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```yaml
login_config:
  max_failed_attempts: 10
  delay: 500 # in milliseconds
```

---

### 3.4 Password Configuration
Here is an example on how to configure the password requirements to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)
```yaml
password_config:
  require_uppercase: true
  require_number: true
  require_symbol: true
  minimum_length: 8
```

---

## 4. When to Use
The decision to use **VigiloAuth** as a Docker instance depends on your specific needs and the environment in which you are operating. Here's a breakdown of when to use **VigiloAuth** as a docker instance:
1. **Ease of Deployment:** You want a quick, easy way to deploy the authentication service without worrying about integrating it directly into your application code.
2. **Isolation:** You want to isolate the authentication service from the rest of your application, either for security, scalability, or management purposes.
3. **No Dependency on Go Environment:** If your application isn't written in Go or you don't want to set up the Go environment, running VigiloAuth as a Docker container allows you to use the authentication service in a language-agnostic way.
4. **Simplified Maintenance:** If you need to quickly deploy or scale the authentication service independently of your application, Docker makes it easy to manage, update, or replace the service with minimal impact on your main application.
5. **Multi-Environment Deployment:** If you are running the service in different environments (e.g., development, staging, production) and want consistency across those environments, Docker can help provide a stable and reproducible configuration.

Use the Docker instance if you want a fast, isolated, and easy-to-deploy solution without the need to integrate the code directly into your application.

---

## 5. Next Steps
After setting up **VigiloAuth**, refer to the [Identity API Endpoints documentation](endpoints/identity/README.md) to learn how to interact with the identity server.