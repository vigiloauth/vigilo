# Static Client Registration
## Endpoint
```
POST https://localhost:<port>/<uri>/clients
```
---
### Headers
| Key             | Value                         | Description                              |
| :-------------- | :---------------------------- | :----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.  |
| Content-Length  | [Content-Length]              | The length of the request body in bytes. |
---
### Request Body
| Field                | Type          | Required | Description                                         |
| :--------------------| :-------------| :--------| :---------------------------------------------------|
| client_name          | string        | Yes      | The client's name.                                  |
| redirect_uris        | string array  | Yes      | The list of redirect URIs. Public clients **must** use HTTPS. |
| client_type          | string        | Yes      | The type of client. Must be either `public` or `confidential`. |
| grant_types          | string array  | Yes      | The grant types associated with the client. Supported values: `authorization_code`, `client_credentials`, `password`, `refresh_token`, `implicit`, `device_code`. |
| scopes               | string array  | No       | The scopes associated with the client. Supported values: `read`, `write`       |
| response_types       | string array  | Yes      | The response types associated with the client. Supported values: `code`, `token`, `id_token`. |
| token_auth_endpoint  | string        | No       | The token authentication endpoint for client credentials flow. Required for `client_credentials` grant type. |
---
### Example Request
```json
{
  "client_name": "Example Client",
  "redirect_uris": [
    "https://example.com/callback",
    "https://example.com/redirect"
  ],
  "client_type": "confidential",
  "grant_types": [
    "authorization_code",
    "client_credentials"
  ],
  "scopes": [
    "read",
    "write"
  ],
  "response_types": [
    "code",
    "token"
  ],
  "token_auth_endpoint": "https://example.com/token"
}
```
---
## Responses
#### HTTP Status Code: `201 Created`
#### Response Body:
```json
{
    "client_id": "c899a9e5-168b-4c85-81f9-1a4ee3b49431",
    "client_name": "Example Client",
    "client_type": "public",
    "redirect_uris": [
        "https://example.com/callback",
        "https://example.com/redirect"
    ],
    "grant_types": [
        "authorization_code",
        "pkce"
    ],
    "response_types": [
        "code",
        "id_token"
    ],
    "created_at": "2025-03-18T17:55:40.843541-07:00",
    "updated_at": "2025-03-18T17:55:40.843541-07:00"
}
```
**Note:** When registering as a `confidential` client, the `client_secret` will be included in the response.

---
## Error Responses:
### 1. Missing One or More Required Fields
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error_code": "validation_error",
    "message": "One or more validation errors occurred",
    "errors": [
        {
            "error_code": "invalid_client",
            "message": "client must be `public` or `confidential`"
        },
        {
            "error_code": "empty_field",
            "message": "`redirect_uris` is empty"
        }
    ]
}
```

### 2. Invalid Redirect URI
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "validation_error",
    "error_description": "One or more validation errors occurred",
    "errors": [
        {
            "error": "invalid_redirect_uri",
            "error_description": "public clients must use HTTPS"
        }
    ]
}
```

### 3. Invalid Grant Types
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "code": "validation_error",
    "error_description": "One or more validation errors occurred",
    "errors": [
        {
            "error": "invalid_grant_type",
            "error_description": "grant type `invalid-grant` is not supported"
        },
        {
            "error": "invalid_response_type",
            "error_description": "`id_token` response type is only allowed with `authorization_code`, `device_code`, or `implicit` grant types"
        }
    ]
}
```

