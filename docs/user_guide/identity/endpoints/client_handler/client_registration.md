# Client Registration

## Endpoint
```http
POST /client/register
```

---

**Description**
This endpoint is responsible for registering the client into the server. If the registration is successful, the response will include a client configuration endpoint and a registration access token which can be used to manage client configurations. 

For information on how to use `client_configuration_endpoint` and `registration_access_token`, please read the following endpoints:
- [Client Read Request](client_read_request.md)

**Note:** Public clients who register with the response type `code`, MUST also use the `authorization_code` and `pkce` grant types.

---

## Headers
| Key             | Value                         | Description                              |
| :-------------- | :---------------------------- | :----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.  |
| Content-Length  | [Content-Length]              | The length of the request body in bytes. |

---

## Request Body
| Field                | Type          | Required | Description                                                                 |
| :--------------------| :-------------| :--------| :--------------------------------------------------------------------------|
| `client_name`          | `string`        | Yes      | The name of the client application being registered.                       |
| `redirect_uris`        | `[]string`   | Yes      | A list of URIs to which the authorization server will redirect the user after successful authorization. Public clients must use HTTPS. |
| `client_type`          | `string`        | Yes      | The type of client. Must be either `public` or `confidential`.             |
| `grant_types`          | `[]string`  | Yes      | The grant types associated with the client. Supported values: `authorization_code`, `client_credentials`, `password`, `refresh_token`, `implicit`, `device_code`, `pkce`. |
| `scopes`               | `[]string`  | No       | The scopes associated with the client. Supported values: `client:read`, `client:write`, `client:delete`, `client:manage`.  |
| `response_types`       | `[]string`  | Yes      | The response types associated with the client. Supported values: `code`, `token`, `id_token`. |
| `token_auth_endpoint`  | `string`    | No       | The token authentication endpoint for the client credentials flow. Required for `client_credentials` grant type. |
| `jwks_uri`             | `string`    | No       | URL pointing to the client's JSON Web Key Set (JWKS), used for signed requests or tokens |
| `logo_uri`             | `string`    | No       | URL pointing to the client's logo, which can be displayed in user-facing interfaces or administrative dashboards. |

---

## Example Request
```http
POST /client/register HTTP/1.1
Accept: application/json
```
```json
{
  "client_name": "Example Client",
  "redirect_uris": [
    "https://example.com/callback",
    "https://example.com/redirect"
  ],
  "client_type": "confidential",
  "grant_types": ["authorization_code", "client_credentials"],
  "scopes": ["client:read", "client:write"],
  "response_types": ["code", "token"],
}
```
**Note:** If no scopes are provided during client registration, VigiloAuth Server defaults to the most restrictive scope (`client:read`).

---

## Responses

### Success Response
#### HTTP Status Code: `201 Created`
#### Response Body:
```json
{
    "client_id": "c899a9e5-168b-4c85",
    "client_name": "Example Client",
    "client_type": "public",
    "redirect_uris": [
        "https://example.com/callback",
        "https://example.com/redirect"
    ],
    "grant_types": ["authorization_code", "pkce"],
    "response_types": ["code", "id_token"],
    "created_at": "2025-03-18T17:55:40.843541-07:00",
    "updated_at": "2025-03-18T17:55:40.843541-07:00",
    "registration_access_token": "eyJhbGciOiJIUzI1NiIsInR5...",
    "client_configuration_endpoint": "https://localhost/oauth/client/register/c899a9e5-168b-4c85",
    "client_id_issued_at": "2025-03-28T13:12:12.065756-04:00"
}
```
**Note:** When registering as a `confidential` client, the `client_secret` will be included in the response.

---

## Error Responses

### 1. Missing One or More Required Fields
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error_code": "validation_error",
    "message": "One or more validation errors occurred.",
    "errors": [
        {
            "error_code": "invalid_client",
            "message": "The client type must be either 'public' or 'confidential'."
        },
        {
            "error_code": "empty_field",
            "message": "The 'redirect_uris' field is empty."
        }
    ]
}
```

### 2. Invalid Redirect URI
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error_code": "validation_error",
    "message": "One or more validation errors occurred.",
    "errors": [
        {
            "error_code": "invalid_redirect_uri",
            "message": "The provided redirect URI is invalid. Public clients must use HTTPS."
        }
    ]
}
```

### 3. Invalid Grant Types
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error_code": "validation_error",
    "message": "One or more validation errors occurred.",
    "errors": [
        {
            "error_code": "invalid_grant_type",
            "message": "The grant type 'invalid-grant' is not supported."
        },
        {
            "error_code": "invalid_response_type",
            "message": "The 'id_token' response type is only allowed with 'authorization_code', 'device_code', or 'implicit' grant types."
        }
    ]
}
```

### 4. Public Client Registering Without PKCE
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "failed to register client",
    "error_details": "public clients are required to use PKCE"
}
```