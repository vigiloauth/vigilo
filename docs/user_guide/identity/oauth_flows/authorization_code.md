# Authorization Code Flow

## Table of Contents
- [Authorization Code Flow](#authorization-code-flow)
  - [Table of Contents](#table-of-contents)
  - [1. Introduction](#1-introduction)
      - [Key Features](#key-features)
  - [2. How the Authorization Code Flow works](#2-how-the-authorization-code-flow-works)
  - [3. Security Considerations](#3-security-considerations)
  - [4. Prerequisites](#4-prerequisites)
  - [5. Supported Metadata](#5-supported-metadata)
  - [6. Example Flow](#6-example-flow)
  - [7. References and Further Reading](#7-references-and-further-reading)

---

## 1. Introduction
The **Authorization Code Flow** is one of the most secure and widely used OAuth 2.0 flows. It is designed for:

- **Confidential Clients:** Applications that can securely store client secrets, such as server-side web applications.
- **Public Clients:** Applications that cannot securely store client secrets, such as mobile apps and single-page applications, when used with **PKCE (Proof Key for Code Exchange)**.

This flow makes sure that sensitive tokens are never exposed to the user's browser or client-side code, making it ideal for both types of clients. By leveraging PKCE, public clients can securely use the Authorization Code Flow without requiring a client secret.

The VigiloAuth Server provides full support for the Authorization Code Flow, allowing developers to easily integrate OAuth 2.0 authentication and authorization into their applications. It handles all key aspects of the flow, including:

- **Authorization Request:** Redirecting users to the authorization server with the required parameters.
- **User Consent:** Managing user consent for requested scopes.
- **Authorization Code Validation:** Validating the authorization code and making sure it matches the client and redirect URI.
- **Token Exchange:** Exchanging the authorization code for access and refresh tokens securely.
- **PKCE Support:** Improving security for public clients by preventing authorization code interception attacks.

By using the VigiloAuth library, developers can focus on building their applications while relying on robust implementations of the Authorization Code Flow that adheres to OAuth 2.0 best practices.

---

#### Key Features
- **Secure Token Handling:** Ensures that tokens are never exposed to the user's browser or client-side code.
- **PKCE Support:** Provides additional security for public clients by preventing authorization code interception attacks. 
- **Customizable:** Allows developers to configure client credentials, redirect URIs, and scopes to suit their application's needs.
- **Error Handling:** Includes detailed error responses for invalid requests, mismatched redirect URIs, invalid client credentials, etc.

To learn more about how the VigiloAuth library supports PKCE, please read the following documentation:
- [OAuth 2.0 Authorization Code Flow with PKCE](authorization_code_pkce.md)
- [Authorization Code Flow Endpoint](../endpoints/authz_handler/authorize_client.md)

---

## 2. How the Authorization Code Flow works
![authorization code flow](../oauth_flows/images/authorization_code_flow.png)

The Authorization Code FLow consists of the following key steps:

1. **User Login:**
  - If the user is not already authenticated, VigiloAuth server will return an error containing the login url.
  - If the user is already authenticated, this step is skipped.

2. **Authorization Request:**
  - After successful authentication, the client application redirects the user to the VigiloAuth endpoint with the required parameters, such as:
    - `client_id`
    - `redirect_uri`
    - `scope`
    - `response_type`
    - `state`

3. **User Consent:**
  - The user reviews and approves (or denies) the requested scopes.
  - If approved, VigiloAuth generates an **authorization code**.

4. **Redirect with Authorization Code:**
  - VigiloAuth redirects the user back to the client's application `redirect_uri`, appending the authorization code and state parameter.

5. **Token Exchange:**
  - The client application sends the authorization code to the token [endpoint](../endpoints/authz_handler/token_exchange.md) along with:
    - `client_id`
    - `redirect_uri`
    - `scope`
    - `response_type`
    - `state`
    - `client_secret` (if confidential)
    - Optional `code_verifier` (if PKCE is used)
  - VigiloAuth validates the request and issues an **access token** along with a **refresh token**

6. **Access Protected Resources:**
  - The client application uses the access token to make authorizes requests to protected resources.

---

## 3. Security Considerations

---

## 4. Prerequisites

---

## 5. Supported Metadata

---

## 6. Example Flow

---

## 7. References and Further Reading
- [OAuth 2.0 Authorization Code Flow with PKCE](authorization_code_pkce.md)
- [Authorization Code Flow Endpoint](../endpoints/authz_handler/authorize_client.md)
- [Token Exchange Endpoint](../endpoints/authz_handler/token_exchange.md)
- [Proof Key for Code Exchange by Public Clients](https://datatracker.ietf.org/doc/html/rfc7636#section-3.1)
- [OAuth Login](../endpoints/oauth_handler/user_authentication.md)