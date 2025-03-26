# Token Exchange
## Endpoint
```
POST /oauth/token
```
---
**Description:** This endpoint handles the token exchange for the OAuth 2.0 Authorization Code Flow, converting an authorization code into access and refresh tokens.

### Query Parameters
| Paramater            | Type          | Required | Description                                                  |
| :--------------------| :-------------| :--------| :------------------------------------------------------------|
| grant_type           | string        | Yes      | Must be `authorization_code`.                                |
| code                 | string        | Yes      | Authorization code received from the [authorize endpoint](authorize_client.md)                      |
| client_id            | string        | Yes      | The unique identifier of the OAuth client.                   |
| client_secret        | string        | Yes      | The client's secret key.                                     |
| redirect_uri         | string        | Yes      | Must match the redirect URI used in the [authorize step](authorize_client.md)                     |
---

### Required Headers
| Key             | Value                         | Description                              |
| :-------------- | :---------------------------- | :----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.  |
| Content-Length  | [Content-Length]              | The length of the request body in bytes. |
---

## Example Request
```
POST /oauth/token
Content-Type: application/json
```
```json
{
    "grant_type": "authorization_code",
    "code": "SplxlOBeZQQYbYS6WxSbIA",
    "redirect_uri": "https://client.example.com/callback",
    "client_id": "s6BhdRkqt3",
    "client_secret": "7Fjfp0ZBr1KtDRbnfVdmIw",
    "state": "xyz123"
}
```
---

## Responses
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

## Error Responses
### 1. No Active Session
#### HTTP Status Code: `401 Unauthorized`
#### Response:
```json
{
    "error": "invalid_session",
    "error_description": "unable to retrieve session data",
    "error_details": "session not found or expired"
}
```

### 2. State Mismatch Between Session and Token Request
#### HTTP Status Code: `400 Bad Request`
#### Response:
```json
{
    "error": "invalid_request",
    "error_description": "state mismatch between session and request"
}
```

### 3. Error Retrieving Authorization Code
#### HTTP Status Code: `500 Internal Server Error`
#### Response:
```json
{
    "error": "internal_server_error",
    "error_description": "failed to retrieve the authorization code",
    "error_details": ""
}
```

### 4. Expired Authorization Code
#### HTTP Status Code: `403 Forbidden`
#### Reponse:
```json
{
    "error": "invalid_grant",
    "error_description": "authorization code not found or expired"
}
```

### 5. Authorization Code Already Used
#### HTTP Status Code: `403 Forbidden`
#### Response:
```json
{
    "error": "invalid_grant",
    "error_description": "authorization code already used"
}
```

### 6. Authorization Code Client ID and Request Client ID Mismatch
#### HTTP Status Code: `403 Forbidden`
#### Response:
```json
{
    "error": "invalid_grant",
    "error_description": "authorization code client ID and request client ID do no match"
}
```

### 7. Authorization Code Redirect URI and Request Redirect URI Mismatch
#### HTTP Status Code: `403 Forbidden`
#### Response:
```json
{
    "error": "invalid_grant",
    "error_description": "authorization code redirect URI and request redirect URI do no match"
}
```

### 8. Invalid Client Secret
#### HTTP Status Code: `403 Forbidden`
#### Response:
```json
{
    "error": "invalid_grant",
    "error_description": "invalid client credentials"
}
```