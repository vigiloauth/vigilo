# Dynamic Client Registration

## Table of Contents
- [Dynamic Client Registration](#dynamic-client-registration)
  - [Table of Contents](#table-of-contents)
  - [1. Introduction](#1-introduction)
  - [2. Dynamic Client Registration Flow](#2-dynamic-client-registration-flow)
  - [3. When to Use](#3-when-to-use)
  - [4. Security Considerations](#4-security-considerations)
      - [4.1 Protecting the Registration Access Token](#41-protecting-the-registration-access-token)
      - [4.2 Validating All Incoming Requests](#42-validating-all-incoming-requests)
      - [4.3 Restricting Client Metadata Updates](#43-restricting-client-metadata-updates)
      - [4.4 Enforcing Strict Validation](#44-enforcing-strict-validation)
      - [4.5 Limiting Client Privileges](#45-limiting-client-privileges)
      - [4.6 Preventing Abuse of Dynamic Registration](#46-preventing-abuse-of-dynamic-registration)
      - [4.7 Securing Confidential Clients](#47-securing-confidential-clients)
      - [4.8 Handling Token Expiration and Revocation](#48-handling-token-expiration-and-revocation)
      - [4.9 Protecting Against CSRF Attacks](#49-protecting-against-csrf-attacks)
      - [4.10 Monitoring and Auditing Client Registrations *(Future Feature)*](#410-monitoring-and-auditing-client-registrations-future-feature)
  - [5. Supported Metadata](#5-supported-metadata)
      - [5.1 Supported Grant Types](#51-supported-grant-types)
      - [5.2 Supported Scopes](#52-supported-scopes)
      - [5.3 Supported Response Types](#53-supported-response-types)
  - [6. Example Flow](#6-example-flow)
      - [6.1 Registering a Client](#61-registering-a-client)
        - [Request:](#request)
        - [Response:](#response)
      - [6.2 Reading Client Details](#62-reading-client-details)
        - [Request:](#request-1)
        - [Response:](#response-1)
      - [6.3 Updating Client Details](#63-updating-client-details)
        - [Request:](#request-2)
        - [Response:](#response-2)
      - [6.4 Deleting a Client](#64-deleting-a-client)
        - [Request:](#request-3)
        - [Response:](#response-3)
      - [6.5 Key Notes](#65-key-notes)

## 1. Introduction
Dynamic Client Registration allows OAuth 2.0 clients to automatically register with VigiloAuth Server, obtaining the information needed for OAuth interactions without manual setup processes. This protocol enables developers to programmatically create client credentials, specify redirect URIs, and define access scopes—streamlining the onboarding process for applications that use your API.

The implementation follows the standards defined in [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) OAuth 2.0 Dynamic Client Registration Protocol. VigiloAuth Server provides a complete suite of endpoints for creating, reading, updating, and deleting client registrations, giving you full control over the client application lifecycle.

---

## 2. Dynamic Client Registration Flow
![dynamic client registration flow](/docs/user_guide/identity/oauth_flows/images/dynamic_client_registration.png)

---

## 3. When to Use
Dynamic Client Registration is particularly valuable for developers using VigiloAuth Server in these scenarios:
- **Rapid Development:** When building applications that need to quickly set up authentication flows without manual configuration steps.
- **Microservices Architecture:** For projects where multiple services need to automatically register with the central auth server during initialization.
- **Dev/Test Environments:** To automatically provision test clients during development and testing cycles, streamlining the workflow.
- **Multi-environment Deployments:** When deploying applications across different environments (development, staging, production) that each need their own client registrations.
- **API-first Applications:** For headless applications or APIs that need programmatic setup without UI interactions.
- **CI/CD Pipelines:** To incorporate automatic client registration as part of your continuous integration and deployment processes.
- **Self-hosted Solutions:** When developers are implementing your auth server library in their own infrastructure and need programmatic control.

Since VigiloAuth Server is designed as a code-first library without a UI, Dynamic Client Registration provides a crucial path for programmatically and easily managing OAuth clients. This eliminates the need for developers to build custom management interfaces just to handle client registration.

---

## 4. Security Considerations
Dynamic Client Registration introduces flexibility but also potential security vulnerabilities if not properly implemented. VigiloAuth Server addresses these concerns through a comprehensive security strategy that balances convenience with robust protection mechanisms. Our implementation follows OAuth 2.0 security best practices while providing appropriate safeguards for automated client registration. The following measures are implemented to ensure your authorization server remains secure even with dynamic registration enabled:

#### 4.1 Protecting the Registration Access Token
- The `registration_access_token` allows clients to manage their registration. VigiloAuth ensures it is securely stored and has a short expiration time. It is immediately revoked if the client is deleted or compromised.
  - **Future Feature:** In the near future, VigiloAuth will support database connections for MySQL and PostgreSQL rather than in memory databases.

#### 4.2 Validating All Incoming Requests
- VigiloAuth authenticates and authorizes all requests using the `registration_access_token`. It is highly recommended to [configure](/docs/user_guide/configuration.md) HTTPS to encrypt communication and reject invalid or missing tokens.

#### 4.3 Restricting Client Metadata Updates
- VigiloAuth prevents updates to immutable fields like `client_id` and `client_secret`. We only allow modifications to specific fields such as `redirect_uris`,`grant_types`, `scopes`, etc.

#### 4.4 Enforcing Strict Validation
- VigiloAuth validates all client metadata during registration and updates, ensuring `redirect_uris` use HTTPS for public clients and reject invalid `grant_types`, `response_types`, or `scopes`.

#### 4.5 Limiting Client Privileges
- It is recommended to grant clients only the minimum privileges necessary. Use scopes to limit access and prevent public clients from requesting confidential privileges.

#### 4.6 Preventing Abuse of Dynamic Registration
- VigiloAuth implements a strict rate-limit for registration requests to prevent abuse, monitoring and logging all registration requests for suspicious activity.

#### 4.7 Securing Confidential Clients
- VigiloAuth protects the `client_secret` for confidential clients by securely storing it (e.g., hashed in the database) and rotating it periodically.

#### 4.8 Handling Token Expiration and Revocation
- VigiloAuth ensures expired or revoked tokens cannot access client registration endpoints. Tokens are immediately revoked if suspicious activity is detected.

#### 4.9 Protecting Against CSRF Attacks
- VigiloAuth uses anti-CSRF tokens and validates the `state` parameter in authorization requests to prevent CSRF attacks.

#### 4.10 Monitoring and Auditing Client Registrations *(Future Feature)*
- While not currently implemented in VigiloAuth Server, monitoring and auditing client registrations is a critical security practice. Developers can and should implement logging and monitoring mechanisms to:
  - Log all client registration, update, and deletion requests.
  - Detect unusual activity, such as a high volume of registrations from a single IP address.
  - Generate alerts for suspicious behavior.

---

## 5. Supported Metadata

The following metadata fields are supported by the VigiloAuth Server for Dynamic Client Registration. These fields align with the [OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591)](https://www.rfc-editor.org/rfc/rfc7591).

| Field Name                   | Description                                                                 | Data Type   | Required                                |
|:-----------------------------|:----------------------------------------------------------------------------|:------------|:----------------------------------------|
| `client_name`                | Human-readable name of the client.                                          | `string`    | Required                                |
| `client_type`                | The type of client to register (e.g., `confidential`, `public`)             | `string`    | Required                                |
| `redirect_uris`              | Array of URIs to which the client can redirect users.                       | `[]string`  | Required                                |
| `grant_types`                | Array of OAuth 2.0 grant types the client can use.                          | `[]string`  | Optional                                |
| `response_types`             | Array of OAuth 2.0 response types the client can use.                       | `[]string`  | Optional                                |
| `client_id`                  | Unique identifier for the client.                                           | `string`    | Auto-generated                          |
| `client_secret`              | Secret used by confidential clients to authenticate with the server.        | `string`    | Auto-generated for confidential clients |
| `token_endpoint_auth_method` | Authentication method for the token endpoint (e.g., `client_secret_basic`). | `string`    | Optional                                |
| `scope`                      | Space-separated list of scopes the client can request.                      | `string`    | Optional                                |

#### 5.1 Supported Grant Types
Grant types are an important aspect of the OAuth 2.0 Dynamic Client Registration Protocol. It specifies the OAuth 2.0 grant types that the client is allowed to use. This field is optional in the protocol, but it plays a critical role in defining how the client interacts with the authorization server. If no grant type is provided during client registration, VigiloAuth Server defaults to the most secure grant type (`authorization_code`).

VigiloAuth currently supports the following grant types (based on OAuth 2.0 standards):
- `authorization_code`:
  - Used by confidential and public clients to exchange an authorization code for an access token.
  - Requires a `redirect_uri` and is commonly used for web and mobile applications.

- `pkce`:
  - An extension of the `authorization_code` grant type that adds an additional layer of security for public clients (e.g., mobile or single-page applications).
  - PKCE mitigates the risk of authorization code interception by requiring the client to generate a `code_verifier` and `code_challenge` during the authorization request.
  - **Use Case:** Recommended for all public clients using the `authorization_code` flow.

- `implicit`:
  - Used by public clients (e.g., single-page applications) to obtain an access token directly without a client secret.
  - **Note:** This grant type is considered less secure and is being deprecated in favor of the Authorization Code Flow with PKCE.

- `client_credentials`:
  - Used by confidential clients to obtain an access token using only the client’s credentials (e.g., client_id and client_secret).
  - Commonly used for machine-to-machine communication.

- `password` (Resource Owner Password Credentials Grant):
  - Allows clients to obtain an access token by directly using the resource owner’s username and password.
  - **Note:** This grant type is discouraged due to security concerns and should only be used in legacy systems.

- `refresh_token`:
  - Allows clients to obtain a new access token using a refresh token when the current access token expires.

- `device_code` (Device Authorization Grant):
  - Used for devices with limited input capabilities (e.g., smart TVs or IoT devices).

#### 5.2 Supported Scopes
Scopes define the permissions granted to a client when it requests access to resources. Each scope represents a specific level of access, and clients can request one or more scopes during the authorization process. If no scopes are provided during client registration, VigiloAuth Server defaults to the most restrictive scope (`client:read`).

VigiloAuth currently supports the following predefined scopes:
- `client:read`:
  - Allows the client to read details of registered clients.
  - **Use Case:** For applications that need to display client information but do not require modification privileges.

- `client:write`:
  - Allows the client to modify details of registered clients, except for immutable fields like `client_id` and `client_secret`.
  - **Use Case:** For applications that need to update client metadata, such as `redirect_uris` or `grant_types`.

- `client:delete`:
  - Allows the client to delete registered clients.
  - **Use Case:** For applications that need to manage the lifecycle of clients, including deletion.

- `client:manage`:
  - Grants full control over all clients, including the ability to read, write, and delete client details.
  - Use Case: For administrative applications or services that require complete control over client registrations.

#### 5.3 Supported Response Types
Response types define the type of response a client expects from the authorization server during the OAuth 2.0 authorization process. They determine whether the client receives an authorization code, an access token, or an ID token. If no response types are provided during client registration, VigiloAuth server defaults to the most common and secure response type (`code`).

VigiloAuth currently supports the following response types:
- `code`
  - The client receives an authorization code, which can be exchanged for an access token and optionally a refresh token.
  - **Use Case:** Used in the Authorization Code Flow, typically for confidential clients or public clients with PKCE.

- `token`:
  - The client receives an access token directly from the authorization server.
  - **Use Case:** Used in the Implicit Flow, typically for single-page applications (SPAs) or other public clients.
  - **Note:** The Implicit Flow is considered less secure and is being deprecated in favor of the Authorization Code Flow with PKCE.

- `id_token`:
  - The client receives an ID token, which contains information about the authenticated user.
  - **Use Case:** Used in OpenID Connect (OIDC) flows to provide user identity information.

---

## 6. Example Flow
This section demonstrates the typical flow for **Dynamic Client Registration** using VigiloAuth Server. The flow includes registering a client, reading its details, updating its metadata, and deleting the client.

#### 6.1 Registering a Client
The client sends a `POST` request to the client registration [endpoint](/docs/user_guide/identity/endpoints/client_handler/client_registration.md) to register itself with the VigiloAuth Server.

##### Request:
```
POST /client/register HTTP/1.1
Content-Type: application/json

{
  "client_name": "My Application",
  "redirect_uris": ["https://example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "client_type": "public",
  "scopes": ["client:read", "client:write"]
}
```

##### Response:
```
HTTP/1.1 201 Created
Content-Type: application/json

{
  "client_id": "123456",
  "client_name": "My Application",
  "client_type": "public",
  "redirect_uris": ["https://example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scopes": ["client:read", "client:write"]
  "client_configuration_endpoint": "https://auth.vigilo.com/oauth/client/register/123456",
  "created_at": "2025-03-18T17:55:40.843541-07:00",
  "updated_at": "2025-03-18T17:55:40.843541-07:00",
  "registration_access_token": "reg-access-token"
  "client_id_issued_at": "2025-03-28T13:12:12.065756-04:00"
}
```

#### 6.2 Reading Client Details
The client sends a `GET` request to the client configuration [endpoint](/docs/user_guide/identity/endpoints/client_handler/client_read_request.md) using the `registration_access_token` to retrieve its details.

##### Request:
```
GET /oauth/client/register/123456 HTTP/1.1
Authorization: Bearer reg-access-token
```

##### Response:
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "client_id": "123456",
  "client_configuration_endpoint": "https://auth.vigilo.com/oauth/client/register/123456",
  "registration_access_token": "reg-access-token"
}
```

#### 6.3 Updating Client Details
The client sends a `PUT` request to the client configuration [endpoint](/docs/user_guide/identity/endpoints/client_handler/client_update_request.md) using the `registration_access_token` to update its metadata (e.g., adding a new `redirect_uri`). It is important to note that values for the fields being updated in this request *replace* the value, rather than augment them.

##### Request:
```
PUT /oauth/client/register/123456 HTTP/1.1
Content-Type: application/json
Authorization: Bearer reg-access-token

{
  "client_name": "My Updated Application",
  "redirect_uris": ["https://example.com/callback", "https://example.com/redirect"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scopes": ["client:read", "client:write"]
}
```

##### Response:
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "client_id": "123456",
  "client_configuration_endpoint": "https://auth.vigilo.com/oauth/client/register/123456",
  "registration_access_token": "reg-access-token"
}
```

#### 6.4 Deleting a Client
The client sends a `DELETE` request to the client configuration [endpoint](/docs/user_guide/identity/endpoints/client_handler/client_delete_request.md) using the `registration_access_token` to delete itself.

##### Request:
```
DELETE /oauth/client/register/123456 HTTP/1.1
Authorization: Bearer reg-access-token
```

##### Response:
```
HTTP/1.1 204 No Content
Cache-Control: no-store
Pragma: no-cache
```

#### 6.5 Key Notes
For more information about our Dynamic Client Registration flow, please view the following documentation to gain a better understanding of each endpoint:
- [Client Registration Request](/docs/user_guide/identity/endpoints/client_handler/client_registration.md)
- [Client Read Request](/docs/user_guide/identity/endpoints/client_handler/client_read_request.md)
- [Client Update Request](/docs/user_guide/identity/endpoints/client_handler/client_update_request.md)
- [Client Delete Request](/docs/user_guide/identity/endpoints/client_handler/client_delete_request.md)


