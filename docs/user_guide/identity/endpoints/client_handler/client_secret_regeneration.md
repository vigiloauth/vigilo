# Regenerate Client Secret

## Endpoint
```
POST /client/regenerate-secret/<client_id>
```
---

## Notes for Developers
- Ensure the `client_id` matches the one registered with the authorization server.
- Confidential clients must securely store their `client_secret` and avoid exposing it in client-side code.
- This endpoint is restricted to clients with the `client:manage` scope.

---

## Headers
| Key             | Value                         | Description                              |
| :-------------- | :---------------------------- | :----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.  |
| Content-Length  | [Content-Length]              | The length of the request body in bytes. |

---

## URL Path Parameters
| Parameter | Type   | Required | Description                                                                 |
| :-------- | :----- | :------- | :-------------------------------------------------------------------------- |
| `client_id` | `string` | Yes      | The unique identifier of the client application. This must match the client ID registered with the authorization server. |

---

## Example Request
```
POST https://localhost:8080/client/regenerate-secret/abc12345def
```

---

## Responses

### Success Response
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

## Error Responses

### 1. Missing Client ID
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error_code": "invalid_request",
    "message": "The 'client_id' parameter is missing from the request."
}
```

### 2. Client Not Found
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error_code": "invalid_client",
    "message": "The provided client ID does not match any registered client."
}
```

### 3. Client Type Not Confidential
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error_code": "unauthorized_client",
    "message": "The client type must be 'confidential' to regenerate a client secret. Public clients do not have a client secret."
}
```

### 4. Client Missing Required Scopes
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error_code": "insufficient_scope",
    "message": "The client does not have the required scope 'client:manage' to perform this operation."
}
```

### 5. Internal Server Error
#### HTTP Status Code: `500 Internal Server Error`
#### Response Body:
```json
{
    "error_code": "internal_server_error",
    "message": "An unexpected error occurred while regenerating the client secret."
}
```
