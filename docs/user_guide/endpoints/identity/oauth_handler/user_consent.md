# User Consent
## Endpoint
```
GET /oauth/consent
POST /oauth/consent
```
___

**Description:** This endpoint handles the user's consent process for an OAuth authorization request, allowing retrieval and submission of user consent for a specific cient and scope.

## GET: Retrieve User Consent
### Query Parameters
| Paramater            | Type          | Required | Description                                                  |
| :--------------------| :-------------| :--------| :------------------------------------------------------------|
| client_id            | string        | Yes      | The unique identifier of the OAuth client.                   |
| redirect_uri         | string        | Yes      | The URI to redirect after authorization.                     |
| scope                | string        | Yes      | The requested access scope(s).                               |

### Required Headers
| Key    | Value                   | Description                   |
| :------| :-----------------------| :-----------------------------|
| Cookie | session=<session_token> | Active user session cookie.

---

## POST: Submit User Consent Decision
### Request Body Parameters
| Field     | Type    | Required  | Description                    |
|:----------|:--------|:----------|:-------------------------------|
| approved  | bool    | Yes       | The user's consent decision.   |
| scopes    | string  | No        | The requested access scope(s). |


### Required Headers
| Key          | Value                   | Description                   |
| :------------| :-----------------------| :-----------------------------|
| Cookie       | session=<session_token> | Active user session cookie.   |
| Content-Type | application/json  | Indicates JSON request body.  |
---

## User Consent Flow
1. Client redirects user to the consent endpoint with the required parameters.
2. Server verifies active user session.
3. GET method returns requested scopes and client information.
4. User chooses to approve or deny the authorization request.
5. POST method submits the consent decision.
6. Redirects back to the client's redirect URI with the appropriate response.

### Example GET Request
```
GET /oauth/consent?client_id=abc123&redirect_uri=https://client.example.com/callback&scope=user:read+user:write
```
### Example POST Request
```
POST /oauth/consent?client_id=abc123&redirect_uri=https://client.example.com/callback&scope=user:read+user:write
```
```json
{
    "approved": true,
    "scopes": "user:read user:write"
}
```

## Responses
### GET Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "client_id": "abc123",
    "client_name": "vigilo auth",
    "redirect_uri": "https://client.example.com/callback",
    "scopes": "user:read user:write",
    "consent_endpoint": "https://localhost/oauth/consent",
    "state": "123asdaszdqw..."
}
```

### POST Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "success": true,
    "redirect_uri": "https://client.example.com/callback?code=123asd324&state=123aaasxdzas"
}
```
---

## Error Responses:
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
### 2. Invalid Request Paramaeters
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "bad_request",
    "error_details": "failed to retrieve consent details",
    "error_description": "missing required OAuth parameters"
}
```
### 3. Invalid Client ID
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_details": "failed to retrieve consent details",
    "error_description": "invalid client ID"
}
```

### 4. User Consent Denied
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "error": "access_denied",
    "redirect_uri": "https://client.example.com/callback?error=access_denied&error_description=user%20denied%20access%20to%20the%20request%20scopes&state=123scdcccce"
}
```