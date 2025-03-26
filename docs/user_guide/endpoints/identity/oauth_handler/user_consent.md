# User Consent

## Endpoint
```
GET /oauth/consent
POST /oauth/consent
```

---

**Description:**  
This endpoint facilitates the OAuth authorization process by allowing users to review and approve or deny access to their resources. It supports both retrieving consent details (via `GET`) and submitting the user's decision (via `POST`).

---

## GET: Retrieve User Consent

### Query Parameters
| Parameter    | Type    | Required | Description                                                                 |
| :----------- | :------ | :------- | :-------------------------------------------------------------------------- |
| client_id    | string  | Yes      | The unique identifier of the OAuth client.                                  |
| redirect_uri | string  | Yes      | The URI to redirect to after authorization. Must match the registered URI.  |
| scope        | string  | Yes      | The requested access scope(s), space-separated.                             |
| state        | string  | No       | A unique string to maintain state between requests and prevent CSRF attacks.|

### Required Headers
| Key    | Value                   | Description                   |
| :----- | :-----------------------| :-----------------------------|
| Cookie | session=<session_token> | Active user session cookie.   |

---

## POST: Submit User Consent Decision

### Request Body Parameters
| Field     | Type    | Required  | Description                                                                 |
| :-------- | :------ | :-------- | :-------------------------------------------------------------------------- |
| approved  | bool    | Yes       | The user's consent decision. `true` for approval, `false` for denial.       |
| scopes    | string  | No        | The requested access scope(s), space-separated.                             |

### Required Headers
| Key          | Value                   | Description                   |
| :----------- | :-----------------------| :-----------------------------|
| Cookie       | session=<session_token> | Active user session cookie.   |
| Content-Type | application/json        | Indicates JSON request body.  |

---

## User Consent Flow

1. The client redirects the user to the consent endpoint with the required parameters.
2. The server verifies the active user session.
3. The `GET` method returns requested scopes and client information.
4. The user chooses to approve or deny the authorization request.
5. The `POST` method submits the user's consent decision.
6. The server redirects back to the client's `redirect_uri` with the appropriate response.

---

### Example GET Request
```
GET /oauth/consent?client_id=abc123&redirect_uri=https://client.example.com/callback&scope=user:read+user:write&state=xyz123
```

### Example POST Request
```
POST /oauth/consent
```
```json
{
    "approved": true,
    "scopes": "user:read user:write"
}
```

---

## Responses

### GET Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "client_id": "abc123",
    "client_name": "Vigilo Auth",
    "redirect_uri": "https://client.example.com/callback",
    "scopes": "user:read user:write",
    "consent_endpoint": "https://localhost/oauth/consent",
    "state": "xyz123"
}
```

---

### POST Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "success": true,
    "redirect_uri": "https://client.example.com/callback?code=123asd324&state=xyz123"
}
```

---

## Error Responses

### 1. No Active User Session
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "login_required",
    "error_description": "Authentication required to continue the authorization flow.",
    "login_url": "https://localhost:<port>/oauth/login"
}
```

### 2. Invalid Request Parameters
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "bad_request",
    "error_details": "Failed to retrieve consent details.",
    "error_description": "Missing required OAuth parameters."
}
```

### 3. Invalid Client ID
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_details": "Failed to retrieve consent details.",
    "error_description": "The provided client ID is invalid or unregistered."
}
```

### 4. User Consent Denied
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "error": "access_denied",
    "redirect_uri": "https://client.example.com/callback?error=access_denied&error_description=user%20denied%20access%20to%20the%20requested%20scopes&state=xyz123"
}
```