# OAuth 2.0 Client Credentials Grant
## Endpoint
```
POST https://localhost:<port>/<uri>/auth/token
```
---
**Description:** This endpoint implements the OAuth 2.0 client credentials flow, allowing authenticated clients to obtain an access token for machine-to-machine communication.

### Headers
| Key             | Value                         |
|:----------------|-------------------------------|
| Content-Type    | application/x-www-form-urlencoded |
| Authorization   | Basic {base64(client_id:client_secret)} |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | 
| Content-Length  | 29                            | 
---
### Request Body
| Field      | Type    | Required  | Description                    |
| :----------|:--------|:----------|:-------------------------------|
| grant_type | string  | Yes       | Must be "client_credentials"   |
---
### Example Request
```
POST /auth/token HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Authorization: Basic dGVzdGNsaWVudDpzZWNyZXQ=

grant_type=client_credentials
```
---
## Responses
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
    "token_type": "Bearer",
    "expires_in": 1800
}
```
#### Note: 
The access token is a JWT that can be used to access protected resources. The `expires_in` field indicates the token expiration time in seconds (30 minutes in this implementation).

---
## Error Responses
### 1. Invalid Grant Type
#### HTTP Status Code: `400 Bad Request`
**Description:** Occurs when the grant_type parameter is missing or not equal to "client_credentials".
#### Response Body:
```json
{
    "error": "unsupported_grant_type",
    "error_description": "unsupported grant type"
}
```

### 2. Invalid Request Format
#### HTTP Status Code: `400 Bad Request`
**Description:** Occurs when the request body cannot be parsed.
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "invalid request format"
}
```

### 3. Invalid Authorization Header
#### HTTP Status Code: `400 Bad Request`
**Description:** Occurs when the Authorization header is missing or not in Basic auth format.
#### Response Body:
```json
{
    "error": "invalid_request",
    "description": "invalid authorization header"
}
```

### 4. Invalid Client Credentials Format
#### HTTP Status Code: `401 Unauthorized`
**Description:** Occurs when the client credentials cannot be decoded or are incorrectly formatted.
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "invalid credentials format"
}
```

### 5. Client Authentication Failed
#### HTTP Status Code: `401 Unauthorized`
**Description:** Occurs when the client ID and secret combination is invalid.
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "invalid client credentials"
}
```

### 6. Unauthorized Client Type
#### HTTP Status Code: `403 Forbidden`
**Description:** Occurs when the client is not of type "confidential".
#### Response Body:
```json
{
    "error": "unauthorized_client",
    "error_description": "client is not type `confidential`"
}
```

### 7. Invalid Grant Type Permission
#### HTTP Status Code: `403 Forbidden`
**Description:** Occurs when the client does not have permission to use the client_credentials grant type.
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "invalid client credentials",
    "error_details": "client does not have required grant type 'client_credentials'"
}
```

### 8. Invalid Scope
#### HTTP Status Code: `403 Forbidden`
**Description:** Occurs when the client does not have the required scope.
#### Response Body:
```json
{
    "error": "invalid_scope",
    "error_description": "invalid client credentials",
    "error_details": "client does not have require scope 'client:manage'
}
```

### 9. Token Generation Error
#### HTTP Status Code: `500 Internal Server Error`
**Description:** Occurs when there is an internal error generating the access token.
#### Response Body:
```json
{
    "error": "internal_server_error",
    "error_description": "An internal server error occurred"
}
```

### 10. Client Does Not Exist
#### HTTP Status Code: `401 Unauthorized`
**Description:** Occurs when the client does not exist with the given `client_id`.
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "invalid client credentials",
    "error_details": "client does not exist with the given ID"
}
```

### 11. Invalid Client Secret
#### HTTP Status Code: `401 Unauthorized`
**Description:** Occurs when the `client_secret` provided is invalid.
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "invalid client credentials",
    "error_details": "invalid `client_secret` provided"
}
```

---
### Notes:
- This implementation follows the OAuth 2.0 specification (RFC 6749) for the client credentials grant type.
- The client must be authenticated using HTTP Basic Authentication.
- No refresh tokens are issued in this flow as it is designed for machine-to-machine communication.
- The token is returned with Cache-Control: no-store to prevent caching of sensitive tokens.
- All error responses follow the OAuth 2.0 error response format.