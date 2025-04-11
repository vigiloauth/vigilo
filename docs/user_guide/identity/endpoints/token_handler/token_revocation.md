#  OAuth 2.0 Token Revocation

## Endpoint
```http
POST /oauth/token/revoke

```

---

## Required Headers
| Key             | Value                              | Description                                     |
| :-------------- | :----------------------------------| :-----------------------------------------------|
| Content-Type    | application/x-www-form-urlencoded  | Indicates that the request body is URL-encoded. |
| Date            | Tue, 03 Dec 2024 19:38:16 GMT      | The date and time the request was made.         |
| Content-Length  | [Content-Length]                   | The length of the request body in bytes.        |

---

## Request Body
| Field        | Type       | Required  | Description                           |
| :------------|:-----------|:----------|:--------------------------------------|
| `token`      | `string`   | Yes       | The requested token to revoke.        |

---

## Example Request
*Note:* The client must have the `tokens:revoke` scope for this request.

#### Example request for confidential clients:
```http
POST /oauth/token/revoke HTTP/1.1
Authorization: Basic dGVzdGNsaWVudDpzZWNyZXQ
Content-Type: application/x-www-form-urlencoded

token=1FF3ZcYmriDTmziexguayay90HCgHJYR2UUGNcEwvC0
```

#### Example request for public clients:
```http
POST /oauth/token/revoke HTTP/1.1
Authorization: Bearer dGVzdGNsaWVudDpzZWNyZXQ
Content-Type: application/x-www-form-urlencoded

token=1FF3ZcYmriDTmziexguayay90HCgHJYR2UUGNcEwvC0
```

---

## Success Response
VigiloAuth will respond with a `200 OK` status code regardless if the token has been successfully blacklisted or if the client submitted an invalid token.
Invalid tokens do not cause an error response since the client cannot handle a response of that kind reasonably.

```http
Status 200 OK
Content-Type: application/json
```

---

## Error Responses

### 1. Invalid Client Credentials for Confidential Clients
#### HTTP Status Code: `401 Unauthorized`
#### Response Body:
```json
{
    "error": "invalid_client",
    "error_description": "failed to authenticate request",
    "error_details": "failed to authenticate client: client credentials are either missing or invalid"
}
```
*Note:* This error is returned for confidentials clients using the basic authorization header with invalid credentials (client ID or client secret).

### 2. Invalid Bearer Token
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "invalid_grant",
    "error_description": "failed to authenticate request",
    "error_details": "failed to validate bearer token: invalid token format"
}
```
*Note:* This error is returned for public clients using the bearer token authorization header with an invalid token.

### 3. Missing Required Scopes
#### HTTP Status Code: `400 Bad Request`
#### Response Body:
```json
{
    "error": "insufficient_scope",
    "error_description": "failed to authenticate request",
    "error_details": "failed to validate client authorization: client does have the required scope(s)"
}
```