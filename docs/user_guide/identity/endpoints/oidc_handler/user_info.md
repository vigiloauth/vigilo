# User Info

## Endpoint
```http
GET /oauth2/userinfo
POST /oauth2/userinfo
```

**Description:**
This endpoint is used to retrieve claims about the authenticated End-User. Access to this endpoint requires a valid Access Token with the openid scope. The claims returned in the response are determined by the scopes granted to the client during the authorization process.

---

## Access Token Placement
The Access Token MUST be sent to the UserInfo Endpoint using one of the following methods:
1. **HTTP Authorization Header (Recommended):** The Access Token is included in the `Authorization` request header field using the `Bearer` authentication scheme. This method is supported for both `GET` and `POST` requests.
```
Authorization: Bearer <access_token>
```
2. **POST Request Body:** For `POST` requests, the Access Token MAY alternatively be included as an `access_token` parameter in the request body using the `application/x-www-form-urlencoded` content type.
```
Content-Type: application/x-www-form-urlencoded
access_token=<access_token>
```
---

## Headers
| Key             | Value                         | Description                               |
| :-------------- | :---------------------------- | :---------------------------------------- |
| `Authorization` | `Bearer <token>`              | The bearer token. **Required** for `GET` requests. **Optional** for `POST` requests if token is in the body. |
| `Content-Type`  | `application/x-www-form-urlencoded` | **Required** for `POST` requests when sending the access token in the body. |
| `Content-Type`  | `application/json`       | **Recommended** for `POST` requests if sending other data (though not standard). |
| `Accept` | `application/json` | **Recommended** to indicate the client prefers a JSON response. |
| `Date` | `[Date Header]` | The date and time the request was made. |
| `Content-Length` | `[Content-Length]` | The length of the request body in bytes. **Required** for `POST` requests with a body. |

---

## Request Body (for POST method)
When using the `POST` method with `Content-Type: application/x-www-form-urlencoded`, the Access Token can be send in the request body:

| Parameter     | Type     | Required | Description       |
|:--------------|:---------|:---------|:------------------|
| `access_token`| `string` | Yes      | The bearer token. |

---

## Example Requests

### Example GET Request (Recommended)
```http
GET /oauth2/userinfo HTTP/1.1
Host: your.auth.server.com
Authorization: Bearer Gp7b5hiURKpWzEXgMJP38En
Accept: application/json
```

### Example POST Request (Token in Body)
```http
POST /oauth2/userinfo HTTP/1.1
Host: your.auth.server.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30 // Example length

access_token=Gp7b5hiURKpWzEXgMJP38En
```

### Example POST Request (Token in Header)
```http
POST /oauth2/userinfo HTTP/1.1
Host: your.auth.server.com
Authorization: Bearer Gp7b5hiURKpWzEXgMJP38En
Accept: application/json
Content-Length: 0 // No body needed if the token is in the header
```

**Note on Scopes:** The claims returned in the UserInfo response depend on the scopes granted to the client during the authorization request. The supported standard OpenID Connect scopes that influence the UserInfo response include:
- `profile`: Access to user's profile (`name`, `first_name`, `middle_name`, `last_name`, `birthdate`, and `updated_at`).
- `email`: Access to the user's email address (`email` and `email_verified`).
- `phone`: Access to the user's phone number (`phone_number` and `phone_number_verified`).
- `address`: Access to the user's address (`formatted`, `street_address`, `locality`, `region`, `postal_code`, and `country`).
- `offline_access`: Access to the requested user's information while they do not have an active session.
- `openid`: **Required** scope to access the UserInfo endpoint. Does not grant access to specific claims by itself.

---

## Responses

### Success Response
#### HTTP Status Code: `200 OK`
#### Response Body:
The response body is a JSON object containing claims about the End-User. The specific claims included depend on the scopes granted to the client.
```json
{
    "sub": "user-1234",
    "username": "john.doe",
    "name": "John Mary Doe",
    "first_name": "John",
    "middle_name": "Mary",
    "family_name": "Doe",
    "birthdate": "2000-12-06",
    "email": "john.doe@email.com",
    "email_verified": true,
    "phone_number": "+14255551212",
    "phone_number_verified": true,
    "updated_at": "1714075783",
    "address": {
        "formatted": "123 Main St\nSpringfield, IL 62704\nUSA",
        "street_address": "123 Main St", 
        "locality": "Springfield",
        "region": "IL",
        "postal_code": "62704",
        "country": "USA"
    }
    // ... other claims based on granted scopes
}
```

---

## Error Responses
Errors are returned in the response body as a JSON object.

| Error Code (`error`)     | HTTP Status Code   | Description (`error_description`) | Notes                                                        |
|:-------------------------|:-------------------|:----------------------------------|:-------------------------------------------------------------|
| `invalid_token`          | `401 Unauthorized` | The Access Token provided is invalid, expired, revoked, or does not match the scope required for this endpoint. | This is the standard error for invalid access tokens at protected resources. Includes cases like missing token, expired token, invalid signature, etc. |
| `insufficient_scope` | `403 Forbidden` | The Access Token does not have the required scopes to access this endpoint or the requested claims. | For UserInfo, this typically means the `openid` scope is missing, or the token lacks scopes needed for specific claims (e.g., `profile`, `email`) if those were requested via the claims parameter. (Though standard practice is to filter claims based on granted scopes). |
| `invalid_request` | `400 Bad Request | The request is missing a required parameter (if sending token in body), includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. | E.g., Missing `access_token` parameter in the POST body when not sent in the header. |
| `server_error` | `500 Internal Server Error` | The authorization server encountered an unexpected condition that prevented it from fulfilling the request. | A catch-all error for internal server issues.