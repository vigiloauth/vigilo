# User Info

## Endpoint
```http
GET /oauth2/userinfo
```

---

**Note:** This endpoint currently only supports the authorization header of type Bearer.

## Headers
| Key             | Value                         | Description                               |
| :-------------- | :---------------------------- | :---------------------------------------- |
| Content-Type    | application/json              | Indicates that the request body is JSON.  |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.   |
| Content-Length  | [Content-Length]              | The length of the request body in bytes.  |
| Authorization   | Bearer <token>                | The bearer token.                         |

---

## Example Request
```http
GET /oauth2/userinfo HTTP/1.1
Authorization: Bearer Gp7b5hiURKpWzEXgMJP38En
```

---

**Note:** The supported scopes follow the Open ID Connect scopes which include:
- `profile`: Access to user's profile (`name`, `first_name`, `middle_name`, `last_name`, `birthdate`, and `updated_at`).
- `email`: Access to the user's email address (`email` and `email_verified`).
- `phone`: Access to the user's phone number (`phone_number` and `phone_number_verified`).
- `address`: Access to the user's address (`formatted`, `street_address`, `locality`, `region`, `postal_code`, and `country`).
- `offline_access`: Access to the requested user's information while they do not have an active session.

## Responses

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "sub": "user-1234",
    "username": "john.doe",
    "name": "John Mary Doe",
    "first_name": "John",
    "middle_name": "Mary",
    "family_name": "Doe",
    "birthdate": "2000-12-06",
    "email": "john.doe@email.com",
    "email_verified": true,
    "phone_number": "+14255551212",
    "phone_number_verified": true,
    "updated_at": "2025-04-25T17:29:43.633415788Z",
    "address": {
        "formatted": "123 Main St\nSpringfield, IL 62704\nUSA",
        "street_address": "123 Main St", 
        "locality": "Springfield",
        "region": "IL",
        "postal_code": "62704",
        "country": "USA"
    },
}
```

---

## Error Responses

### 1. Insufficient Scopes
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "insufficient_scope",
    "error_description": "failed to retrieve the requested user info",
    "error_details": "failed to authorize request: bearer access token has insufficient privileges"
}
```

### 2. Missing Authorization Header
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "missing or invalid authorization header",
    "error_details": "authorization header is missing"
}
```

### 3. Invalid Token Subject
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to retrieve the requested user info",
    "error_details": "failed to authorize request: invalid token subject"
}
```

### 4. Invalid Token Audience
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "failed to retrieve the requested user info",
    "error_details": "failed to authorize request: invalid token audience"
}
```

### 5. Access Token is Expired
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "unauthorized",
    "error_description": "an error occurred validating the access token",
    "error_details": "the token is expired",
}
```

### 6. Internal Server Error
#### HTTP Status Code: `500 Internal Error`
#### Response Body:
```json
{
    "error": "server_error",
    "error_description": "An unexpected error occurred. Please try again later."
}
```