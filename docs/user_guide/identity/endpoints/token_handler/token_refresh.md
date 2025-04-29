# OAuth 2.0 Token Refresh Grant

## Endpoint
```http
POST /oauth/token
```

---

## Headers
| Key             | Value                                   | Description                                                                |
| :-------------- | :---------------------------------------| :--------------------------------------------------------------------------|
| Content-Type    | application/x-www-form-urlencoded       | Indicates that the request body is URL-encoded.                            |
| Authorization   | Basic {base64(client_id:client_secret)} | HTTP Basic Authentication header containing the client ID and secret.      |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT           | The date and time the request was made.                                    |
| Content-Length  | [Content-Length]                        | The length of the request body in bytes.                                   |

---

## Request Body
| Field           | Type       | Required  | Description                                                                     |
| :---------------|:-----------|:----------|:--------------------------------------------------------------------------------|
| `grant_type`    | `string`   | Yes       | Specifies the type of grant being used. Must be set to `refresh_token`.         |
| `scopes`        | `[]string` | Yes       | Specifies the specific scopes the client is requesting.                         |
| `refresh_token` | `string`   | Yes       | The refresh token to use.                                                       |

---

## Example Request
```http
POST /oauth/client/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=clients:read clients:write
&refresh_token=abcs123
&client_id=1234
```

**Note:** For confidential clients, the `client_id` and `client_secret` must be passed in the `Authorization` header using `base64` encoding.

---

## Responses

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Headers:
```
Cache-Control: no-store
Content-Type: application/json
```
#### Response Body:
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 1800
}
```

**Note:**  
The access token is a JWT that can be used to access protected resources. The `expires_in` field indicates the token expiration time in seconds (30 minutes in this implementation).

---

## Error Responses

### 1. Missing One or More Required Parameters
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "one or more required parameters are missing"
}
```

### 2. Unsupported Grant Type in the Request
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "unsupported_grant_type",
    "error_description": "the provided grant type [invalid-grant-type] is not supported"
}
```
*Note:* The field `[invalid-grant-type]` will be replaced with actual requested grant type.

### 3. Invalid Client Secret
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "failed to issue new access and refresh tokens",
    "error_details": "failed to validate client authorization: the client credentials are invalid or incorrectly formatted"
}
```

### 4. Invalid Client ID
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "failed to issue new access and refresh tokens",
    "error_details": "client credentials are either missing or invalid"
}
```

### 5. Invalid Refresh Token
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "failed to issue new access and refresh tokens",
    "error_details": "failed to validate refresh token: invalid token format"
}
```

### 6. Expired Refresh Token
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "failed to issue new access and refresh tokens",
    "error_details": "failed to validate refresh token: the token is expired"
}
```

### 7. Refresh Token is Blacklisted
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "failed to issue new access and refresh tokens",
    "error_details": "failed to validate refresh token: the token is blacklisted"
}
```

### 8. Client is Missing Required Grant Type
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "unauthorized_client",
    "error_description": "failed to issue new access and refresh tokens",
    "error_details": "failed to validate client authorization: client does not have the required grant type"
}
```

### 9. Client is Missing Required Scope
#### HTTP Status Code: `403 Forbidden`
#### Response Body: 
```json
{
    "error": "insufficient_scope",
    "error_description": "failed to issue new access and refresh tokens",
    "error_details": "failed to validate client authorization: client does not have the required scope(s)"
}
```