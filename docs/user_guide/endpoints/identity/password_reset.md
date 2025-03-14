# Password Reset
## Endpoint
```
PATCH https://localhost:<port>/<uri>/auth/reset-password/confirm
```
---
**Description:** This endpoint is used to confirm a password reset request and set a new password for the user's account.
### Headers
| Key             | Value                         | Description                                |
| :-------------- | :---------------------------- | :----------------------------------------- |
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.     |
| Content-Length  | [Content-Length]              | The length of the request body in bytes.  |

---
### Request Body
| Field    | Type   | Required | Description                   |
|----------|--------|----------|-------------------------------|
| email    | string | Yes      | The user's email address.     |
| newPassword | string | Yes      | The new password for the account. |

```json
{
    "email": "email@vigilo.com",
    "new_password": "Pas$_w0rds"
}
```
---
## Responses
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "message": "Password has been reset successfully"
}
```
---
## Error Responses
### 1. Missing new password Field
#### HTTP Status Code: `404 Not Found`
#### Response Body:
```json
{
    "error_code": "EMPTY_FIELD",
    "description": "password cannot be empty"
}
```

### 2. Invalid Password
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
  "error_code": "VALIDATION_ERROR",
  "description": "One or more validation errors occurred.",
  "errors": [
    {
      "error_code": "INVALID_LENGTH",
      "message": "Password must be at least 10 characters",
      "field": "password"
    },
    {
      "error_code": "MISSING_UPPERCASE",
      "message": "Password must contain at least one uppercase letter",
      "field": "password"
    },
    {
      "error_code": "MISSING_NUMBER",
      "message": "Password must contain at least one numeric digit",
      "field": "password"
    },
    {
      "error_code": "MISSING_SYMBOL",
      "message": "Password must contain at least one symbol",
      "field": "password"
    }
  ]
}
```

### 3. Invalid Reset Token
#### HTTP Status Code: `401 Unauthorized`
#### Respone Body:
```json
{
    "error_code": "INVALID_TOKEN",
    "description": "Invalid Token"
}
```

### 4. Password Encryption Error
#### HTTP Status Code: `500 Internal Server Error`
#### Response Body:
```json
{
    "error_code": "INTERNAL_SERVER_ERROR",
    "description": "Failed to encrypt password"
}
```

### 5. User Not Found Error
#### HTTP Status Code: `404 Not Found`
#### Response Body:
```json
{
    "error_code": "USER_NOT_FOUND",
    "description": "User not found",
    "field": "email"
}
```

### 6. Reset Token Deletion Error
#### HTTP Status Code: `500 Internal Server Error`
#### Response Body:
```json
{
    "error_code": "TOKEN_DELETION"
    "description": "Token not found"
}
```