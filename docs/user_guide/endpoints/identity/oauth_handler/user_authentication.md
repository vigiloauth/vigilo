# User Authentication
## Endpoint
```
POST /oauth/login
```
**Description:** Handles user authentication specifically for the OAuth authorization code flow, with additional context parameters to support the ongoing authorization process.

### Headers
| Key             | Value                         | Description                               |
| :-------------- | :---------------------------- | :-----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON.  |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.   |
| Content-Length  | [Content-Length]              | The length of the request body in bytes.  |
---

### Query Parameters
| Paramater            | Type          | Required | Description                                                  |
| :--------------------| :-------------| :--------| :------------------------------------------------------------|
| client_id            | string        | Yes      | The unique identifier of the OAuth client.                   |
| redirect_uri         | string        | Yes      | The URI to redirect after authorization.                     |
---

### Request Body Parameters
| Field     | Type    | Required  | Description                    |
|:----------|:--------|:----------|:-------------------------------|
| user_id   | string  | Yes       | The user's ID.                 |
| email     | string  | Yes       | The user's email address.      |
| password  | string  | Yes       | The password for the account.  |
---

### Login Flow
1. Client redirects user to login page with OAuth context parameters.
2. User enters credentials.
3. Server validates credentials.
4. If successfu, redirects to consent or authorization endpoint.
5. Presevers original OAuth request context.

---

## Example Request
```
POST /oauth/login?client_id=abc123&redirect_uri=https://client.example.com/callback
```
```json
{
    "user_id": "abc123",
    "email": "john.doe@mail.com",
    "password": "password",
}
```
___

## Responses
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "username": "johndoe",
    "email": "john.doe@example.com",
    "token": "eyJhbGciOiJIUzI1NiIsInR5c...",
    "oauth_redirect_url": "https://localhost?client_id=abc123&redirect_uri=https://client.example.com/callback&scope=user:manage&state=xyz123",
    "last_failed_login": "2024-03-15T14:30:22.843541-07:00"
}
```
___

## Error Responses
### 1. Request Body Validation Error
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "validation_error",
    "error_description": "One or more validation errors occurred",
    "errors": [
        {
            "error": "empty_input",
            "error_description": "'password' is empty"
        },
        {
            "error": "invalid_email_format",
            "error_description": "provided email is invalid"
        }
    ]
}
```
### 2. Missing Required OAuth Parameters
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "bad_request",
    "error_description": "missing one or more required parameters"
}
```

### 3. Invalid Credentials
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to authenticate user",
    "error_details": "invalid credentials"
}   
```

### 4. Account is Locked
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to authenticate user",
    "error_details": "account is locked due to too many failed login attempts"
}   
```

### 5. Invalid Credentials
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to authenticate user",
    "error_details": "invalid credentials"
}   
```