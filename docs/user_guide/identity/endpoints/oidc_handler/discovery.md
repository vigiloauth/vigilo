# Discovery Endpoint

## Endpoint
```http
GET /oauth2/.well-known/openid-configuration
```

## Headers
| Key             | Value                         | Description                               |
| :-------------- | :---------------------------- | :---------------------------------------- |
| Content-Type    | application/json              | Indicates that the request body is JSON.  |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.   |
| Content-Length  | [Content-Length]              | The length of the request body in bytes.  |

---

## Example Request
```http
GET /oauth2/.well-known/openid-configuration HTTP/1.1
```

## Responses

#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "issuer": "https://auth.example.com",
    "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
    "token_endpoint": "https://auth.example.com/oauth2/token",
    "user_info_endpoint": "https://auth.example.com/oauth2/userinfo",
    "jwks_uri": "https://auth.example.com/oauth2/.well-known/jwks.json",
    "registration_endpoint": "https://auth.example.com/client/register",
    "scopes_supported": [
        "clients:manage",
        "clients:read",
        "clients:write",
        "clients:delete",
        "users:manage",
        "users:read",
        "users:write",
        "users:delete",
        "tokens:revoke",
        "tokens:introspect",
        "oidc",
        "email",
        "address",
        "profile",
        "phone"
        "offline_access",
    ],
    "response_types_supported": [
        "id_token",
        "code",
        "token"
    ],
    "grant_types_supported": [
        "refresh_token",
        "implicit_flow",
        "password",
        "authorization_code",
        "pkce",
        "client_credentials",
        "device_code"
    ],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "id_token_encryption_alg_values_supported": ["RSA-OAEP"],
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post",
        "none"
    ]
}
```