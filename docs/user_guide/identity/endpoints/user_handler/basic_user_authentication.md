# Basic User Authentication

## Endpoint
```
POST /identity/auth/login
```

---

### Headers
| Key             | Value                         | Description                               |
| :-------------- | :---------------------------- | :-----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON.  |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.   |
| Content-Length  | [Content-Length]              | The length of the request body in bytes.  |

---

### Request Body
| Field     | Type    | Required  | Description                    |
|:----------|:--------|:----------|:-------------------------------|
| `email`     | `string`  | Yes       | The user's email address.      |
| `password`  | `string`  | Yes       | The password for the account.  |

---

### Example Request
```json
{
    "email": "john.doe@email.com",
    "password": "Pas$_w0rds"
}
```

---

## Responses
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "username": "john",
    "email": "john.doe@mail.com",
    "last_failed_login": "0001-01-01T00:00:00Z",
    "roles": [
        "ADMIN"
    ],
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
}
```

---

## Error Responses
### 1. Missing Email Field
#### HTTP Status Code: `404 Not Found`
#### Response Body:
```json
{
    "error": "user_not_found",
    "error_description": "user not found."
}
```

### 2. Invalid Password
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_credentials",
    "error_description": "invalid Credentials"
}
```