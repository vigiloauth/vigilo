# User Registration
## Endpoint
```
POST https://localhost:<port>/<uri>/auth/signup
```
---
### Headers
| Key             | Value                         | Description                              |
| :-------------- | :---------------------------- | :----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.  |
| Content-Length  | [Content-Length]              | The length of the request body in bytes. |
---
### Request Body
| Field     | Type    | Required  | Description                    |
|:----------|:--------|:----------|:-------------------------------|
| username  | string  | Yes       | The user's username.
| email     | string  | Yes       | The user's email address.      |
| password  | string  | Yes       | The password for the account.  |

```json
{
    "username": "test",
    "email": "email@vigilo.com",
    "password": "Pas$_w0rds"
}

```
---
## Responses
#### HTTP Status Code: `201 Created`
#### Response Body:
```json
{
    "username": "John Doe",
    "email": "john.doe@email.com"
}
```
---
## Error Responses
## 1. Missing Username Field
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error_code": "VALIDATION_ERROR",
    "description": "One or more validation errors occurred.",
    "errors": [
        {
            "error_code": "EMPTY_FIELD",
            "message": "username cannot be empty",
            "field": "username"
        }
    ]
}
```

## 2. Invalid Email
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
  "error_code": "VALIDATION_ERROR",
  "description": "One or more validation errors occurred.",
  "errors": [
    {
      "error_code": "INVALID_EMAIL_FORMAT",
      "message": "Invalid email format: emailil.com",
      "field": "email"
    }
  ]
}
```

## 3. Invalid Password
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

## 4. Duplicate User
#### HTTP Status Code: `409 Conflict`
#### Response Body:
```json
{
    "error_code": "DUPLICATE_USER",
    "description": "User already exists with identifier: email",
    "error": "User already exists with identifier: email"
}
```





