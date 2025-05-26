# OAuth 2.0 Client Credentials Grant

## Endpoint
```http
POST /identity/oauth2/token
```

---

**Description:** 
This endpoint implements the OAuth 2.0 client credentials flow, allowing authenticated clients to obtain an access and refresh token for machine-to-machine communication.

---

## Notes for Developers
- This implementation follows the OAuth 2.0 specification (RFC 6749) for the client credentials grant type.
- The client must be authenticated using HTTP Basic Authentication.
- The token is returned with `Cache-Control: no-store` to prevent caching of sensitive tokens.
- All error responses follow the OAuth 2.0 error response format.

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
| Field        | Type       | Required  | Description                                                                     |
| :------------|:-----------|:----------|:--------------------------------------------------------------------------------|
| `grant_type` | `string`   | Yes       | Specifies the type of grant being used. Must be set to `client_credentials`.    |
| `scopes`     | `[]string` | Yes       | Specified the specific scopes the client is requesting.                         |

---

## Example Request
```http
POST /identity/oauth2/token HTTP/1.1
Authorization: Basic dGVzdGNsaWVudDpzZWNyZXQ
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&scope=clients:read clients:write
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
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 1800
}
```

**Note:**  
The access token is a JWT that can be used to access protected resources. The `expires_in` field indicates the token expiration time in seconds (30 minutes in this implementation).

---

## Error Responses

### 1. Invalid Client ID
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "failed to issue token using the client credentials provided",
    "error_details": "failed to authenticate client: credentials are either missing or invalid"
}
```

### 2. Invalid Client Secret
#### HTTP Status Code: `401 Unauthorized`
**Note:** This response only applies to *confidential* clients.
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "failed to issue token using the client credentials provided",
    "error_details": "failed to authenticate client: the client credentials are invalid or incorrectly formatted"
}
```

### 3. Missing Required Grant Type
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "failed to issue token using the client credentials provided",
    "error_details": "failed to validate client: client does not have the required grant type"
}
```

### 4. Insufficient Scopes
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "insufficient_scope",
    "error_description": "failed to issue token using the client credentials provided",
    "error_details": "failed to validate client: client does not have the required scope(s)"
}
```

