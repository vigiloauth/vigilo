# User Registration
## Endpoint
```
POST /identity/auth/signup
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
| `username`       | `string`      | No        | The user's username.                                                     |
| `first_name`     | `string`      | Yes       | The user's first name.                                                   |
| `middle_name`    | `string`      | No        | The user's middle name.                                                  |
| `family_name`    | `string`      | Yes       | The user's family/last name.                                             |
| `birthdate`      | `string`      | No        | The user's birthdate. Must follow the `YYYY-MM-DD` format (ISO 8601). |
| `email`          | `string`      | Yes       | The user's email address.                                                |
| `gender`         | `string`      | No        | The user's gender.                                                       |
| `phone_number`   | `string`      | No        | The user's phone number. Must follow the `E.164` format.                 |
| `password`       | `string`      | Yes       | The password for the account.                                            |
| `nickname`       | `string`      | No        | The user's preferred nickname.                                           |
| `profile`        | `string`      | No        | URL of the user's profile page.                                          |
| `picture`        | `string`      | No        | URL of the user's profile picture.                                       |
| `website`        | `string`      | No        | URL of the user's personal website.                                      |
| `address`        | `UserAddress` | No        | The user's address. See the `UserAddress` schema or example request.     |
| `scopes`         | `[]string`    | No        | The user's requested scopes.                                             |
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
    "nickname": "Johnny",
    "profile": "https://example.com/users/john.doe",
    "picture": "https://example.com/users/john.doe/avatar.jpg",
    "website": "https://john-doe.blog",
    "address": {
      "street_address": "123 Main St",
      "locality": "Springfield",
      "region": "IL",
      "postal_code": "62704",
      "country": "USA"
    },
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

### Response Body Structures
```json
{
    "error": "error_code_string",
    "error_description": "human-readable description of the error",
    "errors": [ // Present for 'validation_error'
        {
            "error": "specific_validation_error_code",
            "error_description": "details about the specific field error"
        }
        // ... potentially more specific errors
    ]
}
```

| HTTP Status Code  | Error Code (`error`)   | Description (`error_description`)       | Notes                                            |
|:------------------|:-----------------------|:----------------------------------------|:-------------------------------------------------|
| `400 Bad Request` | `validation_error`     | one or more validation errors occurred. | Details for specific validation failures (e.g., empty field, invalid format, invalid password complexity) are provided in the nested `errors` array. |
| `409 Conflict`    | `duplicate_user`       | user already exists with identifier: [identifier type, e.g., email]	| Indicates that a user with the provided unique identifier (like username or email) already exists. |

