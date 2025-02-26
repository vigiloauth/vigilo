# User Login
## Endpoint
```
POST https://localhost:<port>/<uri>/login
```
---
### Headers
| Key             | Value                         |
|:----------------|-------------------------------|
| Content-Type    | application/json              | 
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | 
| Content-Length  | 44                            | 
---
### Request Body
| Field    | Type   | Required | Description                   |
|----------|--------|----------|-------------------------------|
| email    | string | Yes      | The user's email address.     |
| password | string | Yes      | The password for the account. |

```json
{
    "email": "email@vigilo.com",
    "password": "Pas$_w0rds"
}
```
---
## Responses
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "token": "your_jwt_token_here"
}
```
---
## Error Responses
### 1. Missing Email Field
#### HTTP Status Code: `404 Not Found`
#### Response Body:
```json
{
    "error_code": "USER_NOT_FOUND",
    "description": "User not found."
}
```
### 2. Invalid Password
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error_code": "INVALID_CREDENTIALS",
    "description": "Invalid Credentials"
}
```