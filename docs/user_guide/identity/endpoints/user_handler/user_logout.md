# User Logout
## Endpoint
```
POST /auth/logout
```
---
**Description:** This is a protect endpoint used for users to logout.
### Headers
| Key             | Value                         | Description                                |
| :-------------- | :---------------------------- | :----------------------------------------- |
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.     |
| Content-Length  | [Content-Length]              | The length of the request body in bytes.  |
---

## Responses
#### HTTP Status Code: `200 OK`
#### Response Headers:
| Key             | Value                         |
|:----------------|-------------------------------|
| Content-Type    | application/json              | 
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | 
---

## Error Responses
### 1. Missing Authorization Header
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_credentials",
    "error_description": "invalid credentials"
}
```

### 2. Invalid Token
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_credentials",
    "error_description": "invalid credentials"
}
```