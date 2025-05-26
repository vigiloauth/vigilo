# VigiloAuth Identity Management Documentation

## Introduction

The **VigiloAuth** Identity Management service is a core component responsible for managing user and client authentication and authorization within your system. It offers comprehensive functionalities, including user registration, login, password management, client registration, and more. This server ensures that only authorized users and clients have access to protected resources, enabling your system to securely manage identities and facilitate secure interactions.

This documentation provides a comprehensive guide to configuring and utilizing the VigiloAuth Identity Management server, covering both user and client management aspects.

---

## Documentation

- **User Management:**
    - [User Registration](../identity/endpoints/user_handler/user_registration.md)
    - [Basic User Authentication](../identity/endpoints/user_handler/basic_user_authentication.md)
    - [OAuth 2.0 User Authentication](../identity/endpoints/user_handler/oauth_user_authentication.md)
    - [User Logout](../identity/endpoints/user_handler/user_logout.md)
    - [Password Reset](../identity/endpoints/user_handler/password_reset.md)
    - [Password Reset Email Request](../identity/endpoints/user_handler/password_reset_request.md)
    - [Account Verification](../identity/endpoints/user_handler/verify.md)

- **Administrative Access:**
    - [Get Audit Events](../identity/endpoints/admin_handler/get_audit_events.md)

- **Client Management:**
    - [Client Registration](../identity/endpoints/client_handler/client_registration.md)
    - [Client Credentials Flow](../identity/endpoints/token_handler/client_credentials_grant.md)
    - [Resource Owner Password Credentials Flow](../identity/endpoints/token_handler/ropc_grant.md)
    - [Client Secret Regeneration](../identity/endpoints/client_handler/client_secret_regeneration.md)
    - **Dynamic Client Configuration**
        - [Client Read Request](../identity/endpoints/client_handler/client_read_request.md)
        - [Client Update Request](../identity/endpoints/client_handler/client_update_request.md)
        - [Client Delete Request](../identity/endpoints/client_handler/client_delete_request.md)

- **Token Management:**
    - [Token Refresh](../identity/endpoints/token_handler/token_refresh.md)
    - [Token Introspection](../identity/endpoints/token_handler/token_introspection.md)
    - [Token Revocation](../identity/endpoints/token_handler/token_revocation.md)

- **Authorization Code Flow:**
    - [Client Authorization](../identity/endpoints/authz_handler/authorize_client.md)
    - [User Consent](../identity/endpoints/consent_handler/user_consent.md)
    - [Token Exchange](../identity/endpoints/token_handler/token_exchange.md)

- **Open ID Connect Endpoints:**
    - [UserInfo Endpoint](../identity/endpoints/oidc_handler/user_info.md)
    - [JWKS Endpoint](../identity/endpoints/oidc_handler/jwks.md)
    - [Discovery Endpoint](../identity/endpoints/oidc_handler/discovery.md)

