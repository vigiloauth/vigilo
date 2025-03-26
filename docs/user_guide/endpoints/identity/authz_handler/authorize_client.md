# Authorize Client
## Endpoint
```
GET /oauth/authorize
```
---
**Description:** This endpoint is used to handle the authorization request in the OAuth 2.0 Authorization Code Flow. It validates the client's authorization request, checks user session and consent, and redirects to the approrpriate URL.

### Query Parameters
| Paramater            | Type          | Required | Description                                                  |
| :--------------------| :-------------| :--------| :------------------------------------------------------------|
| client_id            | string        | Yes      | The unique identifier of the OAuth client.                   |
| redirect_uri         | string        | Yes      | The URI to redirect after authorization.                     |
| scope                | string        | Yes      | The requested access scope(s).                               |
| approved             | boolean       | Yes      | Whether the user has approved the request.                   |
| state                | string        | No       | Opaque value to maintain state between request and callback. |
---

### Required Headers
| Key    | Value                   | Description                   |
| :------| :-----------------------| :-----------------------------|
| Cookie | session=<session_token> | Active user session cookie.
---

### Authorization Flow
1. The client initiates an authorization request with the required parameters.
2. Serves checks if a valid user session exists.
3. If no session exists, returns a login required error with login URL.
4. If the session exists, processes user's consent to the authorization request.
5. Redirects to the specified `redirect_uri` with an authorization code or an error.

---
## Example Request
```
GET https://localhost:<port>/oauth/authorize?client_id=abc123&redirect_uri=https://client.example.com/callback&scope=profile&approved=true&state=xyz
```

## Responses
#### HTTP Status Code: `302 Found`
- Redirect to the client's `redirect_uri` with an authorization code.
- Includes the optional `state` parameter if provided in the original request.

---

## Error Responses
### 1. No Active User Session
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "login_required",
    "error_description": "authentication required to continue the authorization flow",
    "login_url": "https://localhost:<port>/oauth/login"

}
```
### 2. User Consent Not Approved
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "consent_required",
    "error_description": "user consent required for the requested scope",
    "consent_url": "https://localhost:<port>/oauth/consent?client_id=<client_id>&redirect_uri=<redirect_uri>&scope=<scopes>"
}
```

### 3. Resource Owner Denies Consent
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "access_denied",
    "error_description": "the resource owner denied the request"
}
```

### 4. Missing Required OAuth Parameters
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "bad_request",
    "error_description": "missing one or more required parameters"
}
```

### 5. Invalid User ID
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "invalid user ID"
}
```

### 6. Invalid Client ID
#### HTTP Status Code: `404 Forbidden`
#### Response Body:
```json
{
    "error": "unauthorized_client",
    "error_description": "invalid client ID"
}
```

### 7. Missing Required Scopes
#### HTTP Status Code: `404 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_scope",
    "error_description": "client is missing required scopes"
}
```

### 8. Non Confidential Client
#### HTTP Status Code: `404 Forbidden`
#### Response Body:
```json
{
    "error": "unauthorized_client",
    "error_description": "client must be confidential to process the request"
}
```

### 9. Invalid Redirect URI
#### HTTP Status Code: `404 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_redirect_uri",
    "error_description": "invalid redirect URI",
    "error_details": "....."
}
```