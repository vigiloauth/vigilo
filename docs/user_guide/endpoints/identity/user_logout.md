# User Logout
## Endpoint
```
POST https://localhost:<port>/<uri>/logout
```
---
### Headers
| Key             | Value                         |
|:----------------|-------------------------------|
| Authorization   | Bearer <your_jwt_token_here>  | 
| Content-Type    | application/json              | 
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | 
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
    "error_code": "INVALID_CREDENTIALS",
    "description": "Invalid credentials"
}
```
### 2. Invalid Token
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error_code": "INVALID_CREDENTIALS",
    "description": "Invalid credentials"
}
```