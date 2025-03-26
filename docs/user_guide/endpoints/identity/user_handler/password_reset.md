# Password Reset
## Endpoint
```
PATCH /auth/reset-password/confirm
```
---
**Description:** This endpoint is used to confirm a password reset request and set a new password for the user's account.
### Headers
| Key             | Value                         | Description                              |
| :-------------- | :---------------------------- | :----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.  |
| Content-Length  | [Content-Length]              | The length of the request body in bytes. |

---
### Request Body
| Field       | Type    | Required  | Description                       |
|:------------|:--------|:----------|:----------------------------------|
| email       | string  | Yes       | The user's email address.         |
| newPassword | string  | Yes       | The new password for the account. |
---
### Example Request
```json
{
    "email": "john.doe@gmail.com",
    "new_password": "Pas$_w0rds"
}
```
---
## Responses
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "message": "password has been reset successfully"
}
```
---
## Error Responses
### 1. Missing new password Field
#### HTTP Status Code: `404 Not Found`
#### Response Body:
```json
{
    "error": "empty_field",
    "error_description": "password cannot be empty"
}
```

### 2. Invalid Password
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
  "error": "validation_error",
  "error_description": "one or more validation errors occurred.",
  "errors": [
    {
      "error": "invalid_password_length",
      "error_description": "password must be at least 10 characters",
    },
    {
      "error": "missing_required_uppercase",
      "error_description": "password must contain at least one uppercase letter",
    },
    {
      "error": "missing_required_number",
      "error_description": "password must contain at least one numeric digit",
    },
    {
      "error": "missing_required_symbol",
      "error_description": "password must contain at least one symbol",
    }
  ]
}
```

### 3. Invalid Reset Token
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_token",
    "error_description": "invalid Token"
}
```

### 4. Password Encryption Error
#### HTTP Status Code: `500 Internal Server Error`
#### Response Body:
```json
{
    "error": "internal_server_error",
    "error_description": "failed to encrypt password"
}
```

### 5. User Not Found Error
#### HTTP Status Code: `404 Not Found`
#### Response Body:
```json
{
    "error": "user_not_found",
    "error_description": "user not found",
}
```

### 6. Reset Token Deletion Error
#### HTTP Status Code: `500 Internal Server Error`
#### Response Body:
```json
{
    "error": "internal_server_error"
    "error_description": "failed to delete token"
}
```