# VigiloAuth Identity Management Documentation

## Introduction
The **VigiloAuth** Identity Management service is a core component responsible for managing user and client authentication and authorization within your system. It offers comprehensive functionalities, including user registration, login, password management, client registration, and more. This server ensures that only authorized users and clients have access to protected resources, enabling your system to securely manage identities and facilitate secure interactions.

This documentation provides a comprehensive guide to configuring and utilizing the VigiloAuth Identity Management server, covering both user and client management aspects.

## OAuth Flows Overview
- [Dynamic Client Registration](../identity/oauth_flows/dynamic_client_registration.md)
- [Authorization Code Flow](../identity/oauth_flows/authorization_code.md)
- [Authorization Code Flow with PKCE](../identity/oauth_flows/authorization_code_pkce.md)
- [Client Credentials Flow](../identity/oauth_flows/client_credentials.md)
- [Resource Owner Password Credentials Flow](../identity/oauth_flows/ropc_flow.md)


## Documentation
- [Configuration Guide](../../configuration.md)
- **User Management:**
    - [User Registration](../identity/endpoints/user_handler/user_registration.md)
    - [User Login](../identity/endpoints/identity/endpoints/user_handler/user_login.md)
    - [User Logout](../identity/endpoints/user_handler/user_logout.md)
    - [Password Reset](../identity/endpoints/user_handler/password_reset.md)
    - [Password Reset Email Request](../identity/endpoints/user_handler/password_reset_request.md)
    - [Account Verification](../identity/endpoints/user_handler/verify.md)
- **Client Management:**
    - [Client Registration](../identity/endpoints/client_handler/client_registration.md)
    - [Client Credentials Flow](../identity/endpoints/token_handler/client_credentials_grant.md)
    - [Resource Owner Password Credentials Flow](../identity/endpoints/token_handler/ropc_grant.md)
    - [Client Secret Regeneration](../identity/endpoints/client_handler/client_secret_regeneration.md)
    - **Client Configuration**
        - [Client Read Request](../identity/endpoints/client_handler/client_read_request.md)
        - [Client Update Request](../identity/endpoints/client_handler/client_update_request.md)
        - [Client Delete Request](../identity/endpoints/client_handler/client_delete_request.md)
- **Token Management:**
    - [Token Refresh](../identity/endpoints/token_handler/token_refresh.md)
    - [Token Introspection](../identity/endpoints/token_handler/token_introspection.md)
    - [Token Revocation](../identity/endpoints/token_handler/token_revocation.md)
- **Authorization Code Flow:**
    - [Client Authorization](../identity/endpoints/authz_handler/authorize_client.md)
    - [User Authentication](../identity/endpoints/oauth_handler/user_authentication.md)
    - [User Consent](../identity/endpoints/oauth_handler/user_consent.md)
    - [Token Exchange](../identity/endpoints/token_handler/token_exchange.md)

