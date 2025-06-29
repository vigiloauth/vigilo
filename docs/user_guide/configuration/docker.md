# Docker Instance Configuration

## Table of Contents
- [Docker Instance Configuration](#docker-instance-configuration)
  - [Table of Contents](#table-of-contents)
  - [1. Add VigiloAuth to Your Project](#1-add-vigiloauth-to-your-project)
  - [2. Import the Library](#2-import-the-library)
  - [2.1 Providing Required Secrets and Configuration](#21-providing-required-secrets-and-configuration)
      - [2.1.1 Required Environment Variables (Secrets):](#211-required-environment-variables-secrets)
      - [2.1.2 How to Provide Environment Variables:](#212-how-to-provide-environment-variables)
  - [3. Basic Setup Example](#3-basic-setup-example)
    - [3.1 Configuring The Server](#31-configuring-the-server)
    - [3.2 Token Configuration](#32-token-configuration)
    - [3.3 Login Configuration](#33-login-configuration)
    - [3.4 Password Configuration](#34-password-configuration)
    - [3.5 Audit Log Configuration](#35-audit-log-configuration)
  - [4. Next Steps](#4-next-steps)

---

## 1. Add VigiloAuth to Your Project

To add **VigiloAuth** to your project, simply create a `yaml` configuration file, and your desired configuration settings.

---

## 2. Configure the Server

> **Note:**  
> You do **not** need to build or tag the VigiloAuth Docker images locally.  
> The `docker-compose` configuration uses pre-built images from Docker Hub (e.g., `vigiloauth/server:latest` and `vigiloauth/ui:latest`).  
> Simply run `docker-compose up` and Docker will automatically pull the required images if they are not present on your system.

> It is recommended to use the latest version rather than the Docker tag `latest` to avoid issues. 

In your `docker-compose.yaml` file, add **VigiloAuth** as a service:

```yaml
services:
    vigilo-auth:
        image: vigiloauth/server:latest
        container_name: vigilo-auth
        ports:
         - "8080:8080"
        volumes:
         # Mount your YAML configuration file into the container
         - ./<path to your yaml config>:/app/vigilo.yaml

         # Mount your cert and key files into the container.
         # Note: Only use when HTTPS is enabled.
         - ./<path to cert file>:/app/server.cert
         - ./<path to key file>:/app/server.key
        environment:
          # Tell the container where to find the YAML config
          VIGILO_CONFIG_PATH: /app/vigilo.yaml

          # --- REQUIRED SECRETS (Provided via Environment Variables) ---
          # The following secrets MUST be provided as environment variables.
          # Do NOT put these sensitive values directly in this docker-compose.yaml file.
          # Define them in a .env file next to this docker-compose.yaml, or in your shell environment.
          SMTP_USERNAME: ${SMTP_USERNAME}
          SMTP_PASSWORD: ${SMTP_PASSWORD}
          SMTP_FROM_ADDRESS: ${SMTP_FROM_ADDRESS}
          TOKEN_PRIVATE_KEY: ${TOKEN_PRIVATE_KEY} # Base64 encoded RSA private key
          TOKEN_PUBLIC_KEY: ${TOKEN_PUBLIC_KEY} # Base64 encoded RSA public key
```

## 2.1. Providing Required Secrets and Configuration

**VigiloAuth** requires configuration to run correctly. For security, sensitive information (secrets) are not included in the Docker image or the main YAML configuration file. These secrets must be provided to the container at runtime via environment variables.

Other non-sensitive configuration (like ports, timeouts, password policies) can be provided through the YAML configuration file mounted into the container.

#### 2.1.1. Required Environment Variables (Secrets):

You must provide the following environment variables when running the VigiloAuth container. The application uses these for sensitive operations like sending emails and signing tokens.

- `SMTP_USERNAME`: Username for connecting to the SMTP server. (optional)
- `SMTP_FROM_ADDRESS`: The 'From' email address for outgoing emails. (optional)
- `SMTP_PASSWORD`: Password for the SMTP server. (optional)
- `TOKEN_PRIVATE_KEY`: Your RSA private key used for signing tokens, encoded in Base64.
- `TOKEN_PUBLIC_KEY`: Your RSA public key used for verifying tokens, encoded in Base64.


#### 2.1.2. How to Provide Environment Variables:

When using docker-compose, the simplest and recommended way to provide these secrets without putting them directly in the docker-compose.yaml file is to create a .env file in the same directory as your docker-compose.yaml file. Docker Compose will automatically read variables from this file.

```
# .env file (place next to your docker-compose.yaml)
SMTP_USERNAME=your_smtp_user
SMTP_FROM_ADDRESS=auth@yourdomain.com
SMTP_PASSWORD=your_smtp_password_here
TOKEN_PRIVATE_KEY=base64_encoded_private_key_string_here
TOKEN_PUBLIC_KEY=base64_encoded_public_key_string_here
```

## 2.2. Connecting the Frontend (Vigilo-UI) to the Backend

If you would like to use our [admin-UI](https://github.com/vigiloauth/vigilo-ui) to serve our frontend, you need to make sure that it can reach the backend. To allow the frontend to always reach the backend regardless of the container name, you should assign a **network alias** called `vigilo-backend` to your backend container.

```yaml
services:

  vigilo-ui:
    image: vigiloauth/ui:latest
    container_name: vigilo-auth-ui
    ports:
      - "9090:80"
    depends_on:
      - vigilo-auth
    networks:
      vigilo:  # Connect to shared network

  vigilo-auth:
    image: vigiloauth/server:latest
    container_name: vigilo-auth
    ports:
      - "8080:8080"
    volumes:
      - ./vigilo.yaml:/app/vigilo.yaml
      - ./server.crt:/app/server.crt # Required if using HTTPS
      - ./server.key:/app/server.key # Required if using HTTPS
    environment:
      - VIGILO_CONFIG_PATH=/app/vigilo.yaml
      - SMTP_USERNAME=${SMTP_USERNAME}
      - SMTP_PASSWORD=${SMTP_PASSWORD}
      - SMTP_FROM_ADDRESS=${SMTP_FROM_ADDRESS}
      - TOKEN_PRIVATE_KEY=${TOKEN_PRIVATE_KEY}
      - TOKEN_PUBLIC_KEY=${TOKEN_PUBLIC_KEY}
    networks:
      vigilo:
        aliases:
          - vigilo-backend  # 👈 Required alias for frontend-to-backend communication

networks:
  vigilo:
    driver: bridge
```

### Why this works

Your Vigilo Admin-UI container proxies API requests (e.g. `/identity/...`) to `http://vigilo-backend:8080`, which is resolved inside Docker's internal network via the `vigilo-backend` alias.

---

## 3. Basic Setup Example

Here’s a minimal example of how to integrate **VigiloAuth** into your application:

```yaml
log_level: debug # default log level is INFO

server_config:
  port: 8080
  session_cookie_name: test-session-cookie
  domain: auth.example.com
  force_https: true
  read_timeout: 30 # in seconds
  write_timeout: 30 # in seconds
  authorization_code_duration: 30 # in minutes
  enable_request_logging: true # boolean value (true or false)
```

After adding the configuration file to your `docker-compose.yaml` file, simply run the following command in your terminal:
```
docker-compose up
```

---

### 3.1. Configuring The Server
Here is an example on how to configure the server to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)

```yaml
log_level: debug

server_config:
  session_cookie_name: test-session-cookie
  domain: auth.example.com
  force_https: true
  read_timeout: 30
  write_timeout: 30
  authorization_code_duration: 30
  enable_request_logging: true
  cert_file_path: /app/path/to/cert # Path to the certificate file (.crt or .pem) used for HTTPS
  key_file_path: /app/path/to/key # Path to the private key file (.key or .pem) that corresponds to the certificate
```

#### 3.1.1 How to get the certification and private key file:

##### 1. Use a Certificate Authority (CA)

For production environments, get a valid certificate from a trusted CA such as: 
- [Let's Encrypt](https://letsencrypt.org/) *(free)*
- DigiCert, GlobalSign, etc. *(paid)*

##### 2. Self-Signed Certificates *(for testing/dev only)*:

For local development or testing:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key -out server.crt \
  -subj "/CN=auth.example.com"
```

This generates:
- `server.crt` - certificate
- `server.key` - private key

⚠️ Browsers will warn about self-signed certs. Don’t use them in production.

---

### 3.2. Token Configuration
Here is an example on how to configure the token requirements to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)

```yaml
token_config:
  expiration_time: 30 # in minutes
  access_token_duration: 30 # in minutes
  refresh_token_duration: 2 # in days
```

---

### 3.3. Login Configuration
Here is an example on how to configure the login functionality to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)

```yaml
login_config:
  max_failed_attempts: 10
  delay: 500 # in milliseconds
```

---

### 3.4. Password Configuration
Here is an example on how to configure the password requirements to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)

```yaml
password_config:
  require_uppercase: true
  require_number: true
  require_symbol: true
  minimum_length: 8
```

---

### 3.5. Audit Log Configuration
Here is an example on how to configure the Audit Log configuration to suit your needs. To learn more about the configuration options, refer to the [configuration guide](./configuration_guide.md)

```yaml
audit_config:
  retention_period: 90 # in days
```
---

## 4. Next Steps

After setting up **VigiloAuth**, refer to the [Identity API Endpoints documentation](../identity/README.md) to learn how to interact with the identity server.