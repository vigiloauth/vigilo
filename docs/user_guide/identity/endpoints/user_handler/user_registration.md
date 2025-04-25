# User Registration
## Endpoint
```
POST /auth/signup
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
| Field            | Type          | Required  | Description                                                              |
|:-----------------|:--------------|:----------|:-------------------------------------------------------------------------|
| `username`       | `string`      | Yes       | The user's username.                                                     |
| `first_name`     | `string`      | Yes       | The user's first name.                                                   |
| `middle_name`    | `string`      | Yes       | The user's middle name.                                                  |
| `last_name`      | `string`      | Yes       | The user's last name.                                                    |
| `birthdate`      | `string`      | Yes       | The user's birthdate. Must follow the `ISO 8601:2004 YYYY-MM-DD` format. |
| `email`          | `string`      | Yes       | The user's email address.                                                |
| `gender`         | `string`      | Yes       | The user's gender.                                                       |
| `phone_number`   | `string`      | No        | The user's phone number. Must follow the `E.164` format.                 |
| `password`       | `string`      | Yes       | The password for the account.                                            |
| `address`        | `UserAddress` | Yes       | The user's address. For more information, view the example request.      |
| `scopes`         | `[]string`    | Yes       | The user's requested scopes.                                             |
| `roles`          | `[]string`    | No        | The user's requested roles. Defaults to `USER` if left empty.            |

---

### Example Request
```json
{
    "username": "john.doe",
    "first_name": "John",
    "middle_name": "Mary",
    "family_name": "Doe",
    "birthdate": "2000-12-06",
    "email": "john.doe@mail.com",
    "gender": "male",
    "phone_number": "+919367788755",
    "password": "Pas$_w0rds",
    "address": {
      "street_address": "123 Main St",
      "locality": "Springfield",
      "region": "IL",
      "postal_code": "62704",
      "country": "USA",
    }
    "scopes": ["users:read"],
    "roles": ["ADMIN"]
}

```
---
## Responses
#### HTTP Status Code: `201 Created`
#### Response Body:
```json
{
    "username": "john.doe",
    "name": "John Mary Doe",
    "gender": "male",
    "birthdate": "2000-12-06",
    "email": "john.doe@email.com",
    "phone_number": "+919367788755",
    "address": "123 Main St\nSpringfield\nIL 62704\nUSA",
    "token": "abc1234edf"
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

## 3. Invalid Phone Number
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
  "error": "validation_error",
  "error_description": "one or more validation errors occurred.",
  "errors": [
    {
      "error": "invalid_format",
      "error_description": "invalid phone number format",
    }
  ]
}
```

## 4. Invalid Birthdate
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
  "error": "validation_error",
  "error_description": "one or more validation errors occurred.",
  "errors": [
    {
      "error": "invalid_format",
      "error_description": "the birthdate provided is an invalid date",
    }
  ]
}
```


## 5. Invalid Password
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

## 6. Duplicate User
#### HTTP Status Code: `409 Conflict`
#### Response Body:
```json
{
    "error": "duplicate_user",
    "error_description": "user already exists with identifier: email",
}
```





