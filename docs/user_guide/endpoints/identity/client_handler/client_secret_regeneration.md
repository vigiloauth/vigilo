# Regenerate Client Secret
## Endpoint
```
POST /client/{client_id}/regenerate-secret
```
---
### Headers
| Key             | Value                         | Description                              |
| :-------------- | :---------------------------- | :----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.  |
| Content-Length  | [Content-Length]              | The length of the request body in bytes. |
---
### URL Parameters
| Parameter | Type   | Required | Description                           |
| :---------|:-------| :--------| :-------------------------------------|
| client_id | string | Yes      | The ID of the client to regenerate secret for. |
---
---
### Example Request
```
POST https://localhost:8080/clients/{client_id}/regenerate-secret
```
---
## Responses
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
{
    "client_id": "c899a9e5-168b-4c85-81f9-1a4ee3b49431",
    "client_secret": "new_generated_secret_12345",
    "updated_at": "2025-03-21T15:30:22.843541-07:00"
}
```

**Note:** This endpoint can only be used with `confidential` client types, as `public` clients do not have a client secret.

---
## Error Responses:
### 1. Missing Client ID
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_request",
    "error_description": "missing 'client_id' in request"
}
```

### 2. Client Not Found
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "client does not exist with the given ID"
}
```

### 3. Client Type Not Confidential
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "unauthorized_client",
    "error_description": "client is not type 'confidential'"
}
```

### 4. Internal Server Error
#### HTTP Status Code: `500 Internal Server Error`
#### Response Body:
```json
{
    "error": "internal_server_error",
    "error_description": "failed to regenerate client_secret"
}
```

### 5. Client Missing Required Scopes
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "invalid_scope",
    "error_description": "client does not have required scope 'client:manage'"
}
```