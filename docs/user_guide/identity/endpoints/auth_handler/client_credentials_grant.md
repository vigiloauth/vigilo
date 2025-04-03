# OAuth 2.0 Client Credentials Grant

## Endpoint
```
POST /oauth/client/token
```

---

**Description:**  
This endpoint implements the OAuth 2.0 client credentials flow, allowing authenticated clients to obtain an access token for machine-to-machine communication.

---

## Notes for Developers
- This implementation follows the OAuth 2.0 specification (RFC 6749) for the client credentials grant type.
- The client must be authenticated using HTTP Basic Authentication.
- No refresh tokens are issued in this flow as it is designed for machine-to-machine communication.
- The token is returned with `Cache-Control: no-store` to prevent caching of sensitive tokens.
- All error responses follow the OAuth 2.0 error response format.

---

## Headers
| Key             | Value                              | Description                                                                 |
| :-------------- | :--------------------------------- | :--------------------------------------------------------------------------|
| Content-Type    | application/x-www-form-urlencoded | Indicates that the request body is URL-encoded.                            |
| Authorization   | Basic {base64(client_id:client_secret)} | HTTP Basic Authentication header containing the client ID and secret.      |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT     | The date and time the request was made.                                    |
| Content-Length  | [Content-Length]                  | The length of the request body in bytes.                                   |

---

## Request Body
| Field      | Type    | Required  | Description                                                                 |
| :----------|:--------|:----------|:----------------------------------------------------------------------------|
| `grant_type` | `string`  | Yes       | Specifies the type of grant being used. Must be set to `client_credentials`.|

---

## Example Request
```
POST /oauth/client/token HTTP/1.1
Authorization: Basic dGVzdGNsaWVudDpzZWNyZXQ
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

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
    "token_type": "Bearer",
    "expires_in": 1800
}
```

**Note:**  
The access token is a JWT that can be used to access protected resources. The `expires_in` field indicates the token expiration time in seconds (30 minutes in this implementation).

---

## Error Responses

### 1. Invalid Grant Type
#### HTTP Status Code: `400 Bad Request`
**Description:** Occurs when the `grant_type` parameter is missing or not equal to `client_credentials`.
#### Response Body:
```json
{
    "error": "unsupported_grant_type",
    "error_description": "the provided grant type is not supported"
}
```

### 2. Invalid Request Format
#### HTTP Status Code: `400 Bad Request`
**Description:** Occurs when the request body cannot be parsed.
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "the request body format is invalid"
}
```

### 3. Invalid Authorization Header
#### HTTP Status Code: `400 Bad Request`
**Description:** Occurs when the `Authorization` header is missing or not in Basic auth format.
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "the authorization header is invalid or missing"
}
```

### 4. Invalid Client Credentials Format
#### HTTP Status Code: `401 Unauthorized`
**Description:** Occurs when the client credentials cannot be decoded or are incorrectly formatted.
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "the client credentials are invalid or incorrectly formatted"
}
```

### 5. Client Authentication Failed
#### HTTP Status Code: `401 Unauthorized`
**Description:** Occurs when the client ID and secret combination is invalid.
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "The client credentials are invalid."
}
```

### 6. Unauthorized Client Type
#### HTTP Status Code: `403 Forbidden`
**Description:** Occurs when the client is not of type `confidential`.
#### Response Body:
```json
{
    "error": "unauthorized_client",
    "error_description": "The client must be of type 'confidential' to use this grant type."
}
```

### 7. Invalid Grant Type Permission
#### HTTP Status Code: `403 Forbidden`
**Description:** Occurs when the client does not have permission to use the `client_credentials` grant type.
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "The client does not have permission to use the 'client_credentials' grant type."
}
```

### 8. Invalid Scope
#### HTTP Status Code: `403 Forbidden`
**Description:** Occurs when the client does not have the required scope.
#### Response Body:
```json
{
    "error": "insufficient_scope",
    "error_description": "The client does not have the required scope 'client:manage'."
}
```

### 9. Token Generation Error
#### HTTP Status Code: `500 Internal Server Error`
**Description:** Occurs when there is an internal error generating the access token.
#### Response Body:
```json
{
    "error": "internal_server_error",
    "error_description": "An internal server error occurred while generating the access token."
}
```