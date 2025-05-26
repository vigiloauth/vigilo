# Get Audit Events

## Endpoint
```http
GET /identity/admins/audit-events
```

---

**Description:**
This endpoint is responsible for retrieving the servers audit events.

>**Note:** To access this endpoint, users must have the `ADMIN` role associated to them.

---

## Headers
| Key             | Value                         | Description                              |
| :-------------- | :---------------------------- | :----------------------------------------|
| Content-Type    | application/json              | Indicates that the request body is JSON. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT | The date and time the request was made.  |
| Content-Length  | [Content-Length]              | The length of the request body in bytes. |
| Authorization   | Bearer <token>                | The bearer token.                        |

---

## Query Parameters
| Parameter      | Type                | Required | Description                                          |
|:---------------|:--------------------|:---------|:-----------------------------------------------------|
| `from`         | `string` (RFC3339)  | Yes      | Start of the time range (e.g., 2025-04-01T00:00:00Z) |
| `to`           | `string` (RFC3339)  | Yes      | End of the time range (e.g., 2025-04-23T00:00:00Z)   |
| `UserID`       | `string`            | No       | Filter by user ID (e.g., admin-123)                  |
| `EventType`    | `string`            | No       | Filter by event type (e.g., login_attempt)           |
| `Success`      | `bool`              | No       | Filter by success status (true or false)             |
| `IP`           | `string`            | No       | Filter by IP address (e.g., 192.168.1.10)            |
| `RequestID`    | `string`            | No       | Filter by request ID (e.g., req-abc123)              |
| `SessionID`    | `string`            | No       | Filter by session ID (e.g., sess-xyz789)             |
| `limit`        | `int`               | No       | Number of events to return (default: 100)            |
| `offset`       | `int`               | No       | Number of events to skip for pagination (default: 0) |

----

## Implemented Event Types
**Note:** As the development increases, more event types will be added for improved support and event auditing. Below are the current event types that we support.

| Type                       | Description                                               |
|:---------------------------|:----------------------------------------------------------|
| `login_attempt`            | When a user attempts to authenticate into the system.     |
| `password_reset`           | When a user attempts to reset their password.             |
| `registration_attempt`     | When a user attempts to register with the system.         |
| `account_deletion_attempt` | When an account is deleted from the system.               |
| `session_created`          | When a new session is created.                            |
| `session_deleted`          | When a session is deleted.                                |

---

## Example Request
```http
GET /identity/admin/audit-events HTTP/1.1
Accept: application/json
Authorization: Bearer reg-23410913-abewfq.123483

?from=2025-04-01T00:00:00Z&
&to=2025-04-23T00:00:00Z
&UserID=admin123
&EventType=login_attempt
&Success=false
&IP=192.168.1.10
&RequestID=req-abc123
&SessionID=sess-xyz789
&limit=50
&offset=0
```

---

## Responses

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Body:
```json
```

---

## Error Responses

### 1. Insufficient Role
#### HTTP Status Code: `403 Forbidden`
#### Response Body:
```json
{
    "error": "insufficient_role",
    "error_description": "the request requires higher privileges than provided by the access token"
}
```

### 2. Invalid Timestamp Format
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_input",
    "error_description": "failed to retrieve audit events",
    "error_details": "invalid 'from' timestamp - must be in UTC format"
}
```
