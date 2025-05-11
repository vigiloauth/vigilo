# Token Exchange

## Endpoint
```http
POST /oauth2/tokens
```

---

**Description:**  
This endpoint handles the token exchange for the OAuth 2.0 Authorization Code Flow. It converts an authorization code into access and refresh tokens, allowing the client to access protected resources.

---

## Notes for Developers
- Ensure the `redirect_uri` matches the one used during the authorization step.
- Authorization codes are single-use and expire after a short duration.
- The `state` parameter is used to prevent CSRF attacks and maintain state between requests.

---

## Request Body
| Parameter            | Type          | Required | Description                                                                 |
| :--------------------| :-------------| :--------| :--------------------------------------------------------------------------|
| `grant_type`         | `string`      | Yes      | Specifies the type of grant being used. Must be set to `authorization_code`.|
| `code`               | `string`      | Yes      | The authorization code received from the [authorize endpoint](authorize_client.md). |
| `redirect_uri`       | `string`      | Yes      | Must match the redirect URI used in the [authorize step](authorize_client.md). |
| `state`              | `string`      | Yes      | An opaque value used to maintain state between the request and callback. This helps prevent CSRF attacks. |
| `code_verifier`      | string | No       | The code verifier used for PKCE. Required if PKCE was used during the authorization request. |


---

## Required Headers
| Key             | Value                              | Description                                     |
| :-------------- | :----------------------------------| :-----------------------------------------------|
| Content-Type    | application/x-www-form-urlencoded  | Indicates that the request body is URL-encoded. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT      | The date and time the request was made.         |
| Content-Length  | [Content-Length]                   | The length of the request body in bytes.        |

---

## Example Request
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
&state=xyz123
```

### Example Request with PKCE
```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
&state=xyz123
&code_verifier=xyc123
```

**Note:** The client secret is only applicable for confidential clients. Public clients do not inclue the `Authorization` header and must instead send the `client_id` in the body.

---

## Responses

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "access_token": "2YotnFZFEjr1zCsicMWpAA",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
    "scope": "client:read client:write"
}
```

---

## Error Responses

### 1. No Active Session
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_session",
    "error_description": "Unable to retrieve session data.",
    "error_details": "Session not found or expired."
}
```

### 2. State Mismatch Between Session and Token Request
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "State mismatch between session and request."
}
```

### 3. Error Retrieving Authorization Code
#### HTTP Status Code: `500 Internal Server Error`
#### Response Body:
```json
{
    "error": "internal_server_error",
    "error_description": "Failed to retrieve the authorization code."
}
```

### 4. Expired Authorization Code
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "The authorization code is either expired or not found."
}
```

### 5. Authorization Code Already Used
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "The authorization code has already been used."
}
```

### 6. Authorization Code Client ID and Request Client ID Mismatch
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "The authorization code's client ID does not match the request's client ID."
}
```

### 7. Authorization Code Redirect URI and Request Redirect URI Mismatch
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "The authorization code's redirect URI does not match the request's redirect URI."
}
```

### 8. Invalid Client Secret
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "The provided client credentials are invalid."
}
```

### 9. Missing Code Verifier
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "authorization failed for token exchange",
    "error_details": "missing code verifier for PKCE"
}
```

### 10. Code Verifier Does Not Meet Required Length
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "authorization failed for token exchange",
    "error_details": "invalid code verifier length (length): must be between 43 and 128 characters"
}
```

### 11. Invalid Authorization Code
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "authorization failed for token exchange",
    "error_details": "failed to validate authorization code: invalid authorization code"
}
```

### 12. Code Verifier Exceeds Maximum Length
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "authorization failed for token exchange",
    "error_details": "invalid code verifier length (length): must be between 43 and 128 characters"
}
```

### 13. Code Verifier Contains Invalid Characters
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "authorization failed for token exchange",
    "error_details": "invalid characters: only A-Z, a-z, 0-9, '-', and '_' are allowed (Base64 URL encoding)"
}
```