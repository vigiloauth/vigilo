# Authorize Client

## Endpoint
```
GET /oauth/authorize
```

---

**Description:**  
This endpoint is used to handle the authorization request in the OAuth 2.0 Authorization Code Flow. It validates the client's authorization request, checks the user session and consent, and redirects to the appropriate URL.

---

## Notes for Developers
- Ensure the `redirect_uri` matches the one registered with the client.
- Scopes should be space-separated strings.
- The `state` parameter is optional but recommended to prevent CSRF attacks.
- PKCE (Proof Key for Code Exchange) is an additional security mechanism for public clients (e.g., mobile or single-page applications) to prevent authorization code interception attacks.
- If the client is using PKCE, the `code_verifier` must be sent during the token exchange to validate the `code_challenge`.
- Confidential clients (e.g., server-side applications) are not required to use PKCE but may still use it for additional security

---

## Query Parameters
| Parameter            | Type          | Required | Description                                                                 |
| :--------------------| :-------------| :--------| :--------------------------------------------------------------------------|
| `client_id`          | `string`      | Yes      | The unique identifier of the OAuth client.                                 |
| `redirect_uri`       | `string`      | Yes      | The URI to redirect to after authorization. Must match the registered URI. |
| `scope`              | `string`      | Yes      | The requested access scope(s), space-separated.                            |
| `approved`           | `boolean`     | Yes      | Indicates whether the user has approved the authorization request.         |
| `state`              | `string`      | No       | An opaque value used to maintain state between the request and callback. This helps prevent CSRF attacks. |
| `response_type`      | `string`      | Yes      | The client's response type.                                                |
| `code_challenge`     | `string`      | No       | The PKCE code challenge. Required if the client is using PKCE.             |
| `code_challenge_method` | `string`   | No       | The method used to generate the code challenge. Supported values are `plain` and `S256`. Defaults to `plain`. |

---

## Required Headers
| Key    | Value                   | Description                   |
| :----- | :-----------------------| :-----------------------------|
| Cookie | session=<session_token> | Active user session cookie.   |

---

## Authorization Flow
1. The client initiates an authorization request with the required parameters.
2. If the client is using PKCE:
   - The client must include the `code_challenge` and optionally the `code_challenge_method` in the request.
   - If `code_challenge_method` is not provided, it defaults to `plain`.
3. The server checks if a valid user session exists.
4. If no session exists, the server returns a login required error with a login URL.
5. If the session exists, the server processes the user's consent to the authorization request.
6. If the request is valid, the server generates an authorization code. If PKCE is used, the server associates the `code_challenge` and `code_challenge_method` with the authorization code.
7. The server redirects to the specified `redirect_uri` with the authorization code or an error.


----

## Example Request
```
GET /oauth/authorize HTTP/1.1
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

client_id=abc123&
redirect_uri=https://client.example.com/callback&
scope=user:profile&
approved=true&
state=xyz&
response_type=code
```

#### Example Request using PKCE
```
GET /oauth/authorize HTTP/1.1
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

client_id=abc123&
redirect_uri=https://client.example.com/callback&
scope=user:profile&
approved=true&
state=xyz&
response_type=code&
code_challenge=1234abc8902zz&
code_challenge_method=S256
---

## Responses

### Success Response
#### HTTP Status Code: `302 Found`
- Redirects to the client's `redirect_uri` with an authorization code.
- Includes the optional `state` parameter if provided in the original request.

---

## Error Responses

### 1. No Active User Session
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "login_required",
    "error_description": "Authentication is required to continue the authorization flow.",
    "login_url": "https://localhost:<port>/oauth/login"
}
```

### 2. User Consent Not Approved
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "consent_required",
    "error_description": "User consent is required for the requested scope.",
    "consent_url": "https://localhost:<port>/oauth/consent?client_id=<client_id>&redirect_uri=<redirect_uri>&scope=<scopes>"
}
```

### 3. Resource Owner Denies Consent
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "access_denied",
    "error_description": "The resource owner denied the request."
}
```

### 4. Missing Required OAuth Parameters
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "bad_request",
    "error_description": "Missing one or more required parameters."
}
```

### 5. Invalid User ID
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "The provided user ID is invalid."
}
```

### 6. Invalid Client ID
#### HTTP Status Code: `404 Forbidden`
#### Response Body:
```json
{
    "error": "unauthorized_client",
    "error_description": "The provided client ID is invalid."
}
```

### 7. Missing Required Scopes
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "insufficient_scope",
    "error_description": "The client is missing required scopes."
}
```

### 8. Non Confidential Client
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "unauthorized_client",
    "error_description": "The client must be confidential to process the request."
}
```

### 9. Invalid Redirect URI
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_redirect_uri",
    "error_description": "The provided redirect URI is invalid or does not match the one registered with the client."
}
```

### 10. Public Client Missing PKCE Grant Type
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "failed to authorize client",
    "error_details": "public clients are required to use PKCE"
}
```

### 11. Missing Code Challenge
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "failed to authorize client",
    "error_details": "'code_challenge' is required for PKCE"
}
```

### 12. Unsupported Code Challenge Method
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "failed to authorize client",
    "error_details": "invalid code challenge method: <method_name>. Valid methods are 'plain' and 'SHA-256'"
}
```

### 13. Invalid Code Challenge Length
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "failed to authorize client",
    "error_details": "invalid code challenge length (length): must be between 43 and 128 characters"
}
```

### 14. Code Challenge Contains Invalid Characters
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "failed to authorize client",
    "error_details": "invalid characters: only A-Z, a-z, 0-9, '-', and '_' are allowed (Base64 URL encoding)"
}
```