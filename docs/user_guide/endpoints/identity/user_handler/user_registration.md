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
---
### Example Request
```json
{
    "username": "John",
    "email": "john.doe@mail.com",
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
    "error": "validation_error",
    "error_description": "one or more validation errors occurred.",
    "errors": [
        {
            "error": "empty_field",
            "error_description": "username cannot be empty",
        }
    ]
}
```

## 2. Invalid Email
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
  "error": "validation_error",
  "error_description": "one or more validation errors occurred.",
  "errors": [
    {
      "error": "invalid_email_format",
      "error_description": "invalid email format: emailil.com",
    }
  ]
}
```

## 3. Invalid Password
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
  "error": "validation_error",
  "error_description": "one or more validation errors occurred.",
  "errors": [
    {
      "error": "invalid_password_length",
      "error_description": "Password must be at least 10 characters",
    },
    {
      "error": "missing_required_uppercase",
      "error_description": "Password must contain at least one uppercase letter",
    },
    {
      "error": "missing_required_number",
      "error_description": "Password must contain at least one numeric digit",
    },
    {
      "error": "missing_required_symbol",
      "error_description": "Password must contain at least one symbol",
    }
  ]
}
```

## 4. Duplicate User
#### HTTP Status Code: `409 Conflict`
#### Response Body:
```json
{
    "error": "duplicate_user",
    "error_description": "user already exists with identifier: email",
}
```





