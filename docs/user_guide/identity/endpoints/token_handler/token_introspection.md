# OAuth 2.0 Token Introspection

## Endpoint
```http
POST /oauth2/tokens/introspect

```

---

## Required Headers
| Key             | Value                              | Description                                     |
| :-------------- | :----------------------------------| :-----------------------------------------------|
| Content-Type    | application/x-www-form-urlencoded  | Indicates that the request body is URL-encoded. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT      | The date and time the request was made.         |
| Content-Length  | [Content-Length]                   | The length of the request body in bytes.        |

---

## Request Body
| Field        | Type       | Required  | Description                           |
| :------------|:-----------|:----------|:--------------------------------------|
| `token`      | `string`   | Yes       | The requested token to introspect.    |

---

## Example Request
*Note:* The client must have the `tokens:introspect` scope for this request.

#### Example request for confidential clients:
```http
POST /oauth/token/introspect HTTP/1.1
Authorization: Basic dGVzdGNsaWVudDpzZWNyZXQ
Content-Type: application/x-www-form-urlencoded

token=1FF3ZcYmriDTmziexguayay90HCgHJYR2UUGNcEwvC0
```

#### Example request for public clients:
```http
POST /oauth/token/introspect HTTP/1.1
Authorization: Bearer dGVzdGNsaWVudDpzZWNyZXQ
Content-Type: application/x-www-form-urlencoded

token=1FF3ZcYmriDTmziexguayay90HCgHJYR2UUGNcEwvC0
```

---

## Responses

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "active": true,
    "exp": "1744310667",
    "iat": "1744310067",
    "subject": "client-id",
    "iss": "vigilo-auth-server",
    "jti": "1FF3ZcYmriDTmziexguayay90HCgHJYR2UUGNcEwvC0"
}
```

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "active": false,
}
```

*Note:* If the token in the request is valid, but is either expired, or has been previously revoked, `active` will be set to false.

---

## Error Responses

### 1. Invalid Client Credentials for Confidential Clients
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "failed to authenticate request",
    "error_details": "failed to authenticate client: client credentials are either missing or invalid"
}
```
*Note:* This error is returned for confidential clients using the basic authorization header with invalid credentials (client ID or client secret).

### 2. Invalid Bearer Token
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "failed to authenticate request",
    "error_details": "failed to validate bearer token: invalid token format"
}
```
*Note:* This error is returned for public clients using the bearer token authorization header with an invalid token.

### 3. Missing Required Scopes
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "insufficient_scope",
    "error_description": "failed to authenticate request",
    "error_details": "failed to validate client authorization: client does have the required scope(s)"
}
```
