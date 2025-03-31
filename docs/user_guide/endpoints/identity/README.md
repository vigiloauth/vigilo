# VigiloAuth Identity Management Documentation

## Introduction
The **VigiloAuth** Identity Management service is a core component responsible for managing user and client authentication and authorization within your system. It offers comprehensive functionalities, including user registration, login, password management, client registration, and more. This server ensures that only authorized users and clients have access to protected resources, enabling your system to securely manage identities and facilitate secure interactions.

This documentation provides a comprehensive guide to configuring and utilizing the VigiloAuth Identity Management server, covering both user and client management aspects.

## Documentation
- [Configuration Guide](../../configuration.md)
- **User Management:**
    - [User Registration](user_handler/user_registration.md)
    - [User Login](user_handler/user_login.md)
    - [User Logout](user_handler/user_logout.md)
    - [Password Reset](user_handler/password_reset.md)
    - [Password Reset Email Request](user_handler/password_reset_request.md)
- **Client Management:**
    - [Client Registration](client_handler/client_registration.md)
    - [Client Credentials Flow](auth_handler/client_credentials_grant.md)
    - [Client Secret Regeneration](client_handler/client_secret_regeneration.md)
    - **Client Configuration**
        - [Client Read Request](client_handler/client_read_request.md)
        - [Client Update Request](client_handler/client_update_request.md)
        - [Client Delete Request](client_handler/client_delete_request.md)
- **Authorization Code Flow:**
    - [Client Authorization](authz_handler/authorize_client.md)
    - [User Authentication](oauth_handler/user_authentication.md)
    - [User Consent](oauth_handler/user_consent.md)
    - [Token Exchange](authz_handler/token_exchange.md)